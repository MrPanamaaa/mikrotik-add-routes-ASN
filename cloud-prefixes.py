#!/usr/bin/env python3
import sys
import argparse
import subprocess
import json
import ipaddress
import tempfile
import os
import re
import urllib.request
import json
from typing import List, Set

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

def check_dependencies():
    required = ['curl', 'ssh', 'scp']
    missing = []
    for cmd in required:
        if subprocess.run(['which', cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            missing.append(cmd)
    if missing:
        print(f"Ошибка: отсутствуют зависимости: {' '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def is_valid_ipv4(ip: str) -> bool:
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return False
    octets = ip.split('.')
    for octet in octets:
        if re.match(r'^0\d+$', octet):
            return False
        o = int(octet)
        if o < 0 or o > 255:
            return False
    return True


def is_valid_interface_name(name: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_.-]+$', name))


def escape_mikrotik_comment(comment: str) -> str:
    cleaned = ''.join(c for c in comment if 32 <= ord(c) <= 126 or c in '\t\n\r')
    cleaned = ' '.join(cleaned.splitlines()).rstrip()
    for src, dst in [('\\', '\\\\'), ('"', '\\"'), ('$', '\\$'), ('`', '\\`'), ('{', '\\{'), ('}', '\\}')]:
        cleaned = cleaned.replace(src, dst)
    return cleaned


def validate_router_host(host: str) -> bool:
    if is_valid_ipv4(host):
        return True
    if re.match(r'^[a-zA-Z0-9.-]+$', host):
        return True
    return False


def parse_router_address(router_str: str) -> str:
    if '@' in router_str:
        parts = router_str.split('@', 1)
        if not parts[0] or not parts[1]:
            raise ValueError("Некорректный формат USER@HOST")
        host = parts[1]
    else:
        host = router_str
    if not validate_router_host(host):
        raise ValueError(f"Некорректный адрес роутера: {host}")
    return router_str


def get_aws_prefixes() -> List[str]:
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.load(response)
        prefixes = []
        for p in data.get('prefixes', []):
            ip_prefix = p.get('ip_prefix')
            if ip_prefix and '/' in ip_prefix:
                prefixes.append(ip_prefix)
        return prefixes
    except Exception as e:
        print(f"Ошибка при загрузке AWS: {e}", file=sys.stderr)
        sys.exit(1)


def get_oracle_prefixes() -> List[str]:
    url = "https://docs.oracle.com/iaas/tools/public_ip_ranges.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.load(response)
        prefixes = []
        for region in data.get('regions', []):
            for cidr in region.get('cidrs', []):
                ip_prefix = cidr.get('cidr')
                if ip_prefix and '/' in ip_prefix:
                    prefixes.append(ip_prefix)
        return prefixes
    except Exception as e:
        print(f"Ошибка при загрузке Oracle: {e}", file=sys.stderr)
        sys.exit(1)


def get_cloud_prefixes(cloud: str) -> List[str]:
    if cloud == 'aws':
        return get_aws_prefixes()
    elif cloud == 'oracle':
        return get_oracle_prefixes()
    elif cloud == 'all':
        aws = get_aws_prefixes()
        oracle = get_oracle_prefixes()
        return aws + oracle
    else:
        print(f"Неизвестный cloud: {cloud}", file=sys.stderr)
        sys.exit(1)


def aggregate_prefixes(prefixes: List[str]) -> List[str]:
    try:
        nets = []
        for p in prefixes:
            try:
                nets.append(ipaddress.IPv4Network(p, strict=False))
            except Exception:
                continue
        if not nets:
            return []
        collapsed = ipaddress.collapse_addresses(nets)
        return [str(net) for net in collapsed]
    except Exception as e:
        print(f"Ошибка при агрегации: {e}", file=sys.stderr)
        sys.exit(1)


def get_existing_routes(router_str: str, comment: str, gateway: str) -> Set[str]:
    safe_comment = escape_mikrotik_comment(comment)
    cmd = [
        'ssh', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new',
        router_str,
        f'/ip route print without-paging terse proplist=dst-address where comment="{safe_comment}" and gateway="{gateway}"'
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            print(f"⚠️ Ошибка SSH: {result.stderr.strip() or result.stdout.strip()}", file=sys.stderr)
            sys.exit(1)

        existing = set()
        for line in result.stdout.splitlines():
            line = line.rstrip('\r\n')
            if 'dst-address=' in line:
                parts = line.split()
                for part in parts:
                    if part.startswith('dst-address='):
                        raw_prefix = part[len('dst-address='):].strip()
                        if not raw_prefix:
                            continue
                        try:
                            net = ipaddress.IPv4Network(raw_prefix, strict=False)
                            existing.add(str(net))
                        except Exception:
                            continue
        return existing
    except subprocess.TimeoutExpired:
        print("❌ Таймаут подключения к роутеру.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Ошибка получения маршрутов: {e}", file=sys.stderr)
        sys.exit(1)


def upload_and_apply_script(router_str: str, script_content: str, remote_filename: str, count_new: int, count_removed: int):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rsc', delete=False) as tmp:
        tmp.write(script_content)
        tmp_path = tmp.name

    try:
        print(f"📤 Отправка: {count_new} добавить, {count_removed} удалить...", file=sys.stderr)
        scp_cmd = ['scp', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new', tmp_path, f"{router_str}:{remote_filename}"]
        if subprocess.run(scp_cmd, capture_output=True).returncode != 0:
            print("❌ Ошибка отправки файла.", file=sys.stderr)
            sys.exit(1)

        print("⚙️ Применение на роутере...", file=sys.stderr)
        ssh_cmd = ['ssh', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new', router_str, f'import "{remote_filename}"']
        if subprocess.run(ssh_cmd, capture_output=True).returncode != 0:
            print("❌ Ошибка импорта.", file=sys.stderr)
            subprocess.run(['ssh', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new', router_str, f'file remove "{remote_filename}"'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            sys.exit(1)

        print("🗑️ Удаление временного файла...", file=sys.stderr)
        subprocess.run(['ssh', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new', router_str, f'file remove "{remote_filename}"'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    finally:
        try:
            os.unlink(tmp_path)
        except:
            pass


def add_routes(router_str: str, cloud: str, comment: str, gateway: str):
    if not gateway:
        print("Ошибка: шлюз не может быть пустым.", file=sys.stderr)
        sys.exit(1)

    if not (is_valid_ipv4(gateway) or is_valid_interface_name(gateway)):
        print("Ошибка: шлюз должен быть IPv4 или именем интерфейса.", file=sys.stderr)
        sys.exit(1)

    try:
        router_for_ssh = parse_router_address(router_str)
    except ValueError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)

    print("", file=sys.stderr)
    print(f"🔧 Роутер: {router_str}", file=sys.stderr)
    print(f"☁️ Облачный провайдер: {cloud.upper()}", file=sys.stderr)
    print(f"💬 Комментарий: \"{comment}\"", file=sys.stderr)
    print(f"🚪 Шлюз: {gateway}", file=sys.stderr)
    print("", file=sys.stderr)

    # Этап 1: Получение префиксов
    print("📡 Загрузка префиксов...", file=sys.stderr)
    raw_prefixes = get_cloud_prefixes(cloud)
    count_raw = len(raw_prefixes)
    if count_raw == 0:
        print(f"ℹ️ Не найдено IPv4-префиксов для {cloud.upper()}.", file=sys.stderr)
        return
    print(f"✅ Получено {count_raw} IPv4-префиксов от {cloud.upper()}.", file=sys.stderr)

    # Этап 2: Агрегация
    print("🧮 Агрегация...", file=sys.stderr)
    aggregated = aggregate_prefixes(raw_prefixes)
    count_agg = len(aggregated)
    if count_agg == 0:
        print("⚠️ Агрегация не вернула результатов.", file=sys.stderr)
        return
    print(f"✅ Агрегировано: {count_raw} → {count_agg} префиксов.", file=sys.stderr)

    # Этап 3: Получение существующих маршрутов
    print("🔍 Запрос существующих маршрутов...", file=sys.stderr)
    existing_set = get_existing_routes(router_str, comment, gateway)
    unique_existing = len(existing_set)
    print(f"✅ Найдено {unique_existing} существующих маршрутов.", file=sys.stderr)

    # Этап 4: Сравнение
    new_set = set(aggregated)
    to_remove = existing_set - new_set
    to_add = new_set - existing_set
    duplicates = existing_set & new_set

    count_new = len(to_add)
    count_removed = len(to_remove)
    count_dup = len(duplicates)

    if count_new == 0 and count_removed == 0:
        print("ℹ️ Все маршруты актуальны.", file=sys.stderr)
        return

    # Этап 5: Генерация скрипта
    safe_comment = escape_mikrotik_comment(comment)
    prefix = f"{cloud.upper()}"
    remote_filename = f"{prefix}.rsc"

    script_lines = [
        f"# Сгенерировано для {cloud.upper()} | {subprocess.run(['date', '-Iseconds'], capture_output=True, text=True).stdout.strip()}",
        f"# Шлюз: {gateway} | Комментарий: {comment}",
        "",
        f':local cmt "{safe_comment}"',
        f':local gw "{gateway}"',
        ""
    ]

    for prefix in sorted(to_remove):
        script_lines.append(f'/ip route remove [find where comment=$cmt and gateway=$gw and dst-address={prefix}]')

    if to_remove and to_add:
        script_lines.append("")

    for prefix in sorted(to_add):
        script_lines.append(f'/ip route add dst-address={prefix} gateway=$gw comment=$cmt')

    script_content = "\n".join(script_lines) + "\n"

    # Применение
    upload_and_apply_script(router_str, script_content, remote_filename, count_new, count_removed)

    print("", file=sys.stderr)
    print(f"✅ Готово для {cloud.upper()}.", file=sys.stderr)
    print("📊 Сводка:", file=sys.stderr)
    print(f"   • От провайдера:     {count_raw}", file=sys.stderr)
    print(f"   • После агрегации:   {count_agg}", file=sys.stderr)
    print(f"   • Уже на роутере:    {unique_existing} (дубликатов: {count_dup})", file=sys.stderr)
    print(f"   • Удалено:           {count_removed}", file=sys.stderr)
    print(f"   • Добавлено:         {count_new}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Управление маршрутами облаков (AWS, Oracle) на MikroTik.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    p_add = subparsers.add_parser('add', help='Добавить маршруты облака на MikroTik')
    p_add.add_argument('router', help='USER@IP или IP роутера')
    p_add.add_argument('cloud', choices=['aws', 'oracle', 'all'], help='Облачный провайдер')
    p_add.add_argument('comment', help='Комментарий для маршрутов')
    p_add.add_argument('gateway', help='Шлюз (IPv4 или имя интерфейса)')

    args = parser.parse_args()
    check_dependencies()

    if args.command == 'add':
        add_routes(args.router, args.cloud, args.comment, args.gateway)


if __name__ == '__main__':
    main()