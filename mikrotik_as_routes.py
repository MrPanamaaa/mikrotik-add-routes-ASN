#!/usr/bin/env python3
import sys
import argparse
import subprocess
import json
import ipaddress
import tempfile
import os
import re
from typing import List, Set


def check_dependencies():
    required = ['curl', 'ssh', 'scp']
    missing = []
    for cmd in required:
        if subprocess.run(['which', cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            missing.append(cmd)
    if missing:
        print(f"Ошибка: отсутствуют необходимые зависимости: {' '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def is_valid_ipv4(ip: str) -> bool:
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return False
    octets = ip.split('.')
    for octet in octets:
        if re.match(r'^0\d+$', octet):
            return False
        try:
            o = int(octet)
            if o < 0 or o > 255:
                return False
        except ValueError:
            return False
    return True


def is_valid_interface_name(name: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_.-]+$', name))


def normalize_asn(asn_input: str) -> str:
    asn = asn_input.strip()
    if asn.upper().startswith('AS'):
        rest = asn[2:]
        if rest.isdigit() and rest != '':
            return f"AS{rest}"
        else:
            raise ValueError("Некорректный формат AS (ожидается AS123 или 123).")
    else:
        if asn.isdigit():
            return f"AS{asn}"
        else:
            raise ValueError("Некорректный формат AS (ожидается AS123 или 123).")


def get_prefixes(asn: str) -> List[str]:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    try:
        result = subprocess.run(
            ['curl', '-sS', url],
            capture_output=True,
            text=True,
            check=True
        )
        data = json.loads(result.stdout)
        prefixes = []
        for item in data.get('data', {}).get('prefixes', []):
            prefix = item.get('prefix', '')
            if '.' in prefix and ':' not in prefix:
                prefixes.append(prefix)
        return prefixes
    except subprocess.CalledProcessError as e:
        print(f"Ошибка curl: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Ошибка JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка в prefixes: {e}", file=sys.stderr)
        sys.exit(1)


def aggregate_prefixes_stdin() -> List[str]:
    if sys.stdin.isatty():
        print("Ошибка: функция aggregate-prefixes должна использоваться через pipe.", file=sys.stderr)
        print("Пример: echo '192.0.2.0/24' | python3 prefixes.py aggregate-prefixes", file=sys.stderr)
        sys.exit(1)

    try:
        lines = sys.stdin.read().splitlines()
        nets = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                try:
                    net = ipaddress.IPv4Network(stripped, strict=False)
                    nets.append(net)
                except (ValueError, ipaddress.NetmaskValueError):
                    continue

        if not nets:
            return []

        collapsed = ipaddress.collapse_addresses(nets)
        return [str(net) for net in collapsed]

    except Exception as e:
        print(f"Ошибка в aggregate-prefixes: {e}", file=sys.stderr)
        sys.exit(1)


def aggregate_prefixes_list(prefixes: List[str]) -> List[str]:
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


def escape_mikrotik_comment(comment: str) -> str:
    cleaned = ''.join(c for c in comment if 32 <= ord(c) <= 126 or c in '\t\n\r')
    cleaned = ' '.join(cleaned.splitlines())
    cleaned = cleaned.rstrip()
    cleaned = (cleaned
               .replace('\\', '\\\\')
               .replace('"', '\\"')
               .replace('$', '\\$')
               .replace('`', '\\`')
               .replace('{', '\\{')
               .replace('}', '\\}')
               .replace('[', '\\[')
               .replace(']', '\\]'))
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
        raise ValueError(f"Некорректный адрес роутера '{router_str}'")
    return router_str


def get_existing_routes(router_str: str, comment: str, gateway: str) -> Set[str]:
    safe_comment = escape_mikrotik_comment(comment)
    cmd = [
        'ssh',
        '-o', 'ConnectTimeout=60',
        '-o', 'StrictHostKeyChecking=accept-new',
        router_str,
        f'/ip route print without-paging terse proplist=dst-address where comment="{safe_comment}" and gateway="{gateway}"'
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            print(f"⚠️ Ошибка SSH при получении маршрутов: {result.stderr.strip() or result.stdout.strip()}", file=sys.stderr)
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
        print("❌ Таймаут при подключении к роутеру.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Ошибка при получении существующих маршрутов: {e}", file=sys.stderr)
        sys.exit(1)


def upload_and_apply_script(router_str: str, script_content: str, remote_filename: str, count_new: int, count_removed: int):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rsc', delete=False) as tmp:
        tmp.write(script_content)
        tmp_path = tmp.name

    try:
        # Отправка
        print(f"📤 Отправка: {count_new} добавить, {count_removed} удалить...", file=sys.stderr)
        scp_cmd = [
            'scp',
            '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=accept-new',
            tmp_path,
            f"{router_str}:{remote_filename}"
        ]
        result = subprocess.run(scp_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Ошибка: не удалось отправить файл.", file=sys.stderr)
            sys.exit(1)

        # Применение
        print("⚙️ Применение на роутере...", file=sys.stderr)
        ssh_cmd = [
            'ssh',
            '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=accept-new',
            router_str,
            f'import "{remote_filename}"'
        ]
        result = subprocess.run(ssh_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Ошибка: импорт не удался.", file=sys.stderr)
            # Очистка на роутере
            subprocess.run([
                'ssh', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new',
                router_str, f'file remove "{remote_filename}"'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            sys.exit(1)

        # Удаление временного файла на роутере
        print("🗑️ Удаление временного файла...", file=sys.stderr)
        subprocess.run([
            'ssh', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new',
            router_str, f'file remove "{remote_filename}"'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    finally:
        # Удаление локального временного файла
        try:
            os.unlink(tmp_path)
        except:
            pass


def add_routes(router_str: str, asn_input: str, comment: str, gateway: str):
    if not gateway:
        print("Ошибка: шлюз не может быть пустым.", file=sys.stderr)
        sys.exit(1)

    if not (is_valid_ipv4(gateway) or is_valid_interface_name(gateway)):
        print(f"Ошибка: шлюз '{gateway}' должен быть корректным IPv4-адресом или именем интерфейса (только буквы, цифры, '-', '_').", file=sys.stderr)
        sys.exit(1)

    try:
        router_for_ssh = parse_router_address(router_str)
        asn = normalize_asn(asn_input)
    except ValueError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)

    print("", file=sys.stderr)
    print(f"🔧 Целевой роутер: {router_str}", file=sys.stderr)
    print(f"🌍 AS: {asn}, комментарий: \"{comment}\"", file=sys.stderr)
    print(f"🚪 Шлюз: {gateway}", file=sys.stderr)
    print("", file=sys.stderr)

    # Этап 1: Получение префиксов
    print("📡 Запрос префиксов для {} через RIPE Stat...".format(asn), file=sys.stderr)
    raw_prefixes = get_prefixes(asn)
    count_raw = len(raw_prefixes)
    if count_raw == 0:
        print(f"ℹ️ Для AS {asn} не найдено активных IPv4-префиксов.", file=sys.stderr)
        return
    print(f"✅ Получено {count_raw} IPv4-префиксов от RIPE.", file=sys.stderr)

    # Этап 2: Агрегация
    print("🧮 Агрегация префиксов...", file=sys.stderr)
    aggregated = aggregate_prefixes_list(raw_prefixes)
    count_agg = len(aggregated)
    if count_agg == 0:
        print("⚠️ Агрегация не вернула результатов.", file=sys.stderr)
        return
    print(f"✅ Агрегировано: {count_raw} → {count_agg} префиксов.", file=sys.stderr)

    # Этап 3: Существующие маршруты
    print("🔍 Запрос существующих маршрутов с comment=\"{}\" и gateway=\"{}\"... (Процесс может длиться продолжительное время. Дождитесь выполнения. Таймаут 5 минут!)".format(comment, gateway), file=sys.stderr)
    existing_set = get_existing_routes(router_str, comment, gateway)
    unique_existing = len(existing_set)
    print(f"✅ Найдено {unique_existing} уникальных маршрутов с нужным comment и gateway.", file=sys.stderr)

    # Этап 4: Сравнение
    new_set = set(aggregated)
    to_remove = existing_set - new_set
    to_add = new_set - existing_set
    duplicates = existing_set & new_set

    count_new = len(to_add)
    count_removed = len(to_remove)
    count_dup = len(duplicates)

    if count_new == 0 and count_removed == 0:
        print("ℹ️ Все маршруты актуальны. Нечего менять.", file=sys.stderr)
        print("📊 Сводка:", file=sys.stderr)
        print(f"   • От RIPE:         {count_raw}", file=sys.stderr)
        print(f"   • После агрегации: {count_agg}", file=sys.stderr)
        print(f"   • Уже существуют:  {count_dup}", file=sys.stderr)
        return

    # Этап 5: Генерация скрипта
    safe_comment = escape_mikrotik_comment(comment)
    as_num = asn[2:] if asn.startswith('AS') else asn
    remote_filename = f"AS{as_num}.rsc"

    script_lines = [
        f"# Сгенерировано для AS {asn} | {subprocess.run(['date', '-Iseconds'], capture_output=True, text=True).stdout.strip()}",
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
    print(f"✅ Готово для {asn}.", file=sys.stderr)
    print("📊 Сводка:", file=sys.stderr)
    print(f"   • От RIPE:               {count_raw}", file=sys.stderr)
    print(f"   • После агрегации:       {count_agg}", file=sys.stderr)
    print(f"   • Уникальных на роутере: {unique_existing}", file=sys.stderr)
    print(f"       из них дубликатов:   {count_dup}", file=sys.stderr)
    print(f"   • Удалено:               {count_removed}", file=sys.stderr)
    print(f"   • Добавлено:             {count_new}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        prog='prefixes.py',
        description="Управление маршрутами MikroTik по данным RIPE Stat."
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    p_prefixes = subparsers.add_parser('prefixes', help='Получить IPv4-префиксы AS')
    p_prefixes.add_argument('asn', help='Номер AS (например, AS123 или 123)')

    p_agg = subparsers.add_parser('aggregate-prefixes', help='Агрегировать префиксы из stdin')

    p_agg_asn = subparsers.add_parser('aggregate-prefixes-asn', help='Получить и агрегировать префиксы AS')
    p_agg_asn.add_argument('asn', help='Номер AS')

    p_add = subparsers.add_parser('add', help='Добавить маршруты на MikroTik')
    p_add.add_argument('router', help='USER@IP_РОУТЕРА (например, admin@192.168.88.1)')
    p_add.add_argument('asn', help='Номер AS')
    p_add.add_argument('comment', help='Комментарий для маршрутов')
    p_add.add_argument('gateway', help='Шлюз (IPv4 или имя интерфейса)')

    args = parser.parse_args()
    check_dependencies()

    if args.command == 'prefixes':
        try:
            asn = normalize_asn(args.asn)
            prefixes = get_prefixes(asn)
            for p in prefixes:
                print(p)
        except ValueError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'aggregate-prefixes':
        aggregated = aggregate_prefixes_stdin()
        for p in aggregated:
            print(p)

    elif args.command == 'aggregate-prefixes-asn':
        try:
            asn = normalize_asn(args.asn)
            raw = get_prefixes(asn)
            if not raw:
                print(f"Предупреждение: для AS {asn} не найдено активных IPv4-префиксов.", file=sys.stderr)
                return
            count_before = len(raw)
            print(f"Получено {count_before} IPv4-префиксов для AS {asn}", file=sys.stderr)
            aggregated = aggregate_prefixes_list(raw)
            if not aggregated:
                print(f"Предупреждение: агрегация не вернула результатов для AS {asn}.", file=sys.stderr)
                return
            count_after = len(aggregated)
            print(f"Агрегация для AS {asn}: {count_before} → {count_after} префиксов", file=sys.stderr)
            for p in aggregated:
                print(p)
        except ValueError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'add':
        add_routes(args.router, args.asn, args.comment, args.gateway)


if __name__ == '__main__':
    main()