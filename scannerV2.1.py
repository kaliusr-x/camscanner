import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import os
import time
import requests
from requests.exceptions import RequestException
import sys

def clear_line():
    """Очищает текущую строку в консоли"""
    sys.stdout.write("\r" + " " * 100 + "\r")
    sys.stdout.flush()

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Отображает прогресс-бар в консоли"""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()
    if iteration == total:
        print()

def get_thread_count():
    """Запрашивает у пользователя количество потоков"""
    while True:
        try:
            threads = input("Введите количество потоков для сканирования (по умолчанию 500): ").strip()
            if threads == "":
                return 500
            threads = int(threads)
            if threads < 1 or threads > 10000:
                print("Ошибка: количество потоков должно быть от 1 до 10000")
            else:
                return threads
        except ValueError:
            print("Ошибка: введите целое число")

def scan_ip_port(ip, port, timeout=1):
    """Проверяет, открыт ли порт на указанном IP-адресе"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            return result == 0
    except:
        return False

def check_protection(ip, port, timeout=2):
    """Проверяет, требуется ли авторизация для доступа"""
    try:
        if port in [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 443, 8080, 8081, 8888]:
            # HTTP/HTTPS проверка
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{ip}:{port}"
            response = requests.get(url, timeout=timeout, verify=False)
            
            # Поиск признаков авторизации
            auth_signs = ['login', 'user', 'pass', 'auth', 'password', 'username', 'log in']
            if any(sign in response.text.lower() for sign in auth_signs):
                return "protected"
            if response.status_code == 401 or response.status_code == 403:
                return "protected"
            return "open"
            
        elif port == 554:
            # RTSP проверка
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((str(ip), port))
                s.send(b"OPTIONS * RTSP/1.0\r\n\r\n")
                data = s.recv(1024).decode().lower()
                if '401 unauthorized' in data or 'www-authenticate' in data:
                    return "protected"
                return "open"
                
        else:
            return "open"
            
    except RequestException:
        return "open"
    except:
        return "unknown"

def parse_ip_range(ip_range):
    """Разбирает диапазон IP-адресов или CIDR-нотацию"""
    ip_range = ip_range.strip()
    try:
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            start = ipaddress.IPv4Address(start_ip.strip())
            end = ipaddress.IPv4Address(end_ip.strip())
            return [ipaddress.IPv4Address(ip) for ip in range(int(start), int(end) + 1)]
        elif '/' in ip_range:
            return list(ipaddress.ip_network(ip_range, strict=False).hosts())
        else:
            return [ipaddress.IPv4Address(ip_range)]
    except Exception as e:
        print(f"Ошибка разбора диапазона '{ip_range}': {e}")
        return []

def read_ip_ranges_from_file(filename="ip_ranges.txt"):
    """Читает IP-диапазоны из файла"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ОШИБКА] Файл {filename} не найден!")
        return []
    except Exception as e:
        print(f"Ошибка чтения файла: {e}")
        return []

def scan_ips(ip_list, ports, max_threads):
    """Основная функция сканирования IP-адресов и портов"""
    # Этап 1: Сканирование портов
    open_ports = {}
    total_tasks = len(ip_list) * len(ports)
    completed_tasks = 0
    last_print_time = time.time()
    
    print("Начато сканирование портов...")
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {}
        for ip in ip_list:
            ip_str = str(ip)
            open_ports[ip_str] = {}
            for port in ports:
                future = executor.submit(scan_ip_port, ip, port)
                futures[future] = (ip_str, port)
        
        for future in as_completed(futures):
            ip_str, port = futures[future]
            if future.result():
                open_ports[ip_str][port] = "scan_complete"
            completed_tasks += 1
            
            # Обновление прогресс-бара каждые 0.5 секунд
            current_time = time.time()
            if current_time - last_print_time > 0.5 or completed_tasks == total_tasks:
                elapsed = current_time - last_print_time
                progress_percent = completed_tasks / total_tasks * 100
                
                # Расчет оставшегося времени
                if completed_tasks > 0:
                    time_per_task = elapsed / completed_tasks
                    remaining_seconds = time_per_task * (total_tasks - completed_tasks)
                    remaining_str = f"Осталось: {int(remaining_seconds)} сек"
                else:
                    remaining_str = "Осталось: расчет..."
                
                print_progress_bar(
                    completed_tasks, 
                    total_tasks, 
                    prefix="Сканирование портов:",
                    suffix=remaining_str
                )
                last_print_time = current_time
    
    clear_line()
    print("Сканирование портов завершено!")
    
    # Этап 2: Проверка защиты
    protection_tasks = sum(len(ports) for ports in open_ports.values())
    if protection_tasks == 0:
        print("Открытых портов не найдено, пропускаем проверку защиты")
        return {}
    
    print("Проверка защиты на открытых портах...")
    completed_protection = 0
    last_print_time = time.time()
    
    with ThreadPoolExecutor(max_workers=min(200, max_threads)) as executor:
        protection_futures = {}
        for ip_str, ports_dict in open_ports.items():
            for port, status in ports_dict.items():
                if status == "scan_complete":
                    future = executor.submit(check_protection, ip_str, port)
                    protection_futures[future] = (ip_str, port)
        
        total_protection = len(protection_futures)
        for future in as_completed(protection_futures):
            ip_str, port = protection_futures[future]
            protection_status = future.result()
            open_ports[ip_str][port] = protection_status
            completed_protection += 1
            
            # Обновление прогресс-бара
            current_time = time.time()
            if current_time - last_print_time > 0.5 or completed_protection == total_protection:
                elapsed = current_time - last_print_time
                progress_percent = completed_protection / total_protection * 100
                
                # Расчет оставшегося времени
                if completed_protection > 0:
                    time_per_task = elapsed / completed_protection
                    remaining_seconds = time_per_task * (total_protection - completed_protection)
                    remaining_str = f"Осталось: {int(remaining_seconds)} сек"
                else:
                    remaining_str = "Осталось: расчет..."
                
                print_progress_bar(
                    completed_protection, 
                    total_protection, 
                    prefix="Проверка защиты:",
                    suffix=remaining_str
                )
                last_print_time = current_time
    
    clear_line()
    print("Проверка защиты завершена!")
    
    # Фильтрация и сортировка результатов
    results = {}
    for ip_str, ports_dict in open_ports.items():
        if ports_dict:
            # Оставляем только открытые порты с определенным статусом
            filtered_ports = {p: s for p, s in ports_dict.items() if s in ["open", "protected"]}
            if filtered_ports:
                # Сортируем порты по номеру
                sorted_ports = sorted(filtered_ports.items())
                results[ip_str] = sorted_ports
    
    # Сортировка IP-адресов
    sorted_results = {}
    for ip in sorted(results.keys(), key=lambda x: [int(part) for part in x.split('.')]):
        sorted_results[ip] = results[ip]
    
    return sorted_results

def save_results(results, open_filename='open.txt', locked_filename='locked.txt'):
    """Сохраняет результаты в два файла: открытые и защищенные порты"""
    try:
        # Подготовка данных для сохранения
        open_data = []
        locked_data = []
        
        for ip, ports in results.items():
            open_ports = []
            locked_ports = []
            
            for port, status in ports:
                if status == "open":
                    open_ports.append(str(port))
                elif status == "protected":
                    locked_ports.append(str(port))
            
            if open_ports:
                open_data.append(f"{ip}: {', '.join(open_ports)}")
            if locked_ports:
                locked_data.append(f"{ip}: {', '.join(locked_ports)}")
        
        # Сохранение в файлы
        if open_data:
            with open(open_filename, 'w') as f:
                f.write("\n".join(open_data))
            print(f"Открытые порты сохранены в: {os.path.abspath(open_filename)}")
        else:
            print("Нет открытых портов для сохранения")
        
        if locked_data:
            with open(locked_filename, 'w') as f:
                f.write("\n".join(locked_data))
            print(f"Защищенные порты сохранены в: {os.path.abspath(locked_filename)}")
        else:
            print("Нет защищенных портов для сохранения")
        
        return True
    except Exception as e:
        print(f"Ошибка сохранения: {e}")
        return False

def print_results(results):
    """Выводит результаты в консоль в удобном формате"""
    if not results:
        print("Результатов для вывода нет")
        return
    
    print("\n" + "=" * 70)
    print(" " * 25 + "РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
    print("=" * 70)
    
    # Статистика
    total_ips = len(results)
    open_count = 0
    protected_count = 0
    
    for ip, ports in results.items():
        for port, status in ports:
            if status == "open":
                open_count += 1
            elif status == "protected":
                protected_count += 1
    
    print(f"Всего IP-адресов: {total_ips}")
    print(f"Открытых портов: {open_count}")
    print(f"Защищенных портов: {protected_count}")
    print("=" * 70)
    
    # Детали по открытым портам
    if open_count > 0:
        print("\nОТКРЫТЫЕ ПОРТЫ (без авторизации):")
        for ip, ports in results.items():
            open_ports = [str(port) for port, status in ports if status == "open"]
            if open_ports:
                print(f"  {ip}: {', '.join(open_ports)}")
    
    # Детали по защищенным портам
    if protected_count > 0:
        print("\nЗАЩИЩЕННЫЕ ПОРТЫ (требуют авторизации):")
        for ip, ports in results.items():
            protected_ports = [str(port) for port, status in ports if status == "protected"]
            if protected_ports:
                print(f"  {ip}: {', '.join(protected_ports)}")
    
    print("\n" + "=" * 70)

def main():
    try:
        # Настройки
        RANGES_FILE = "ip_ranges.txt"
        OPEN_FILE = "open.txt"
        LOCKED_FILE = "locked.txt"
        SCAN_PORTS = [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 443, 554, 8000, 8080, 8081, 8888]
        
        print("=" * 70)
        print(" " * 20 + "СКАНЕР IP-КАМЕР v2.1")
        print("=" * 70)
        
        # Запрос количества потоков
        max_threads = get_thread_count()
        print(f"Используется потоков: {max_threads}")
        print("-" * 70)
        
        # Чтение IP-диапазонов
        print(f"\nЗагрузка IP-диапазонов из {RANGES_FILE}...")
        ip_ranges = read_ip_ranges_from_file(RANGES_FILE)
        
        if not ip_ranges:
            print("Файл диапазонов пуст или не найден!")
            return
        
        # Парсинг диапазонов
        all_ips = []
        for ip_range in ip_ranges:
            ips = parse_ip_range(ip_range)
            all_ips.extend(ips)
            print(f"  Добавлено {len(ips)} IP из диапазона: {ip_range}")
        
        if not all_ips:
            print("Нет IP-адресов для сканирования!")
            return
        
        print(f"\nВсего IP для сканирования: {len(all_ips)}")
        print(f"Сканируемые порты: {', '.join(map(str, SCAN_PORTS))}")
        print("-" * 70)
        
        # Старт сканирования
        results = scan_ips(all_ips, ports=SCAN_PORTS, max_threads=max_threads)
        
        # Сохранение результатов
        print("\nСохранение результатов...")
        save_success = save_results(results, OPEN_FILE, LOCKED_FILE)
        
        # Вывод результатов
        if results:
            print_results(results)
            if save_success:
                print("Готово! Результаты сохранены и отображены выше.")
            else:
                print("Результаты отображены, но возникли проблемы при сохранении файлов!")
        else:
            print("Открытых портов не найдено")
        
        input("\nНажмите Enter для выхода...")
    except KeyboardInterrupt:
        print("\nСканирование прервано пользователем!")
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        input("Нажмите Enter для выхода...")

if __name__ == "__main__":
    main()