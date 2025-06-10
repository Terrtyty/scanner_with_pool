from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from tqdm import tqdm
import psutil

MIN_PORT = 1
MAX_PORT = 65535

start_port = 0
end_port = 0

target = input("Оберіть IP: ")

while start_port < MIN_PORT or start_port > MAX_PORT:
    try:
        start_port = int(input(f"Оберіть початковий порт: "))
        if start_port < MIN_PORT or start_port > MAX_PORT:
            print(f"Потрібно ввести число в діапазоні {MIN_PORT}-{MAX_PORT}.")
    except ValueError:
        print("Потрібно ввести ціле число.")

while end_port < MIN_PORT or end_port > MAX_PORT:
    try:
        end_port = int(input(f"Оберіть кінцевий порт: "))
        if end_port < MIN_PORT or end_port > MAX_PORT:
            print(f"Потрібно ввести число в діапазоні {MIN_PORT}-{MAX_PORT}.")
    except ValueError:
        print("Потрібно ввести ціле число.")

ping_timeout = int(input("Час відповіді: "))

open_ports = []


def get_process_name(port):
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
            return psutil.Process(conn.pid).name()
    return None


def scan_port(port):
    packet = IP(dst=target)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=ping_timeout, verbose=0)
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            process_name = get_process_name(port)
            open_ports.append((port, process_name))
            send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)


with ThreadPoolExecutor(max_workers=500) as executor:
    futures = [executor.submit(scan_port, port)
               for port in range(start_port, end_port + 1)]
    for _ in tqdm(as_completed(futures), total=len(futures), desc="Сканування портів:", unit="port"):
        pass

if open_ports:
    for port, process_name in open_ports:
        print(f"Порт {port} відкритий. Програма: {process_name}")
else:
    print("Відкритих портів не знайдено.")
