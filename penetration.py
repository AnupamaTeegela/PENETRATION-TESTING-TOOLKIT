import socket
import hashlib
import requests
import os
from concurrent.futures import ThreadPoolExecutor

# 1. Port Scanner
def port_scanner(target, ports):
    print(f"\n[+] Scanning ports on {target}")
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((target, port))
            print(f"[+] Port {port} is OPEN")
            sock.close()
        except:
            pass

# 2. Directory Bruteforcer
def dir_bruteforce(url, wordlist):
    print(f"\n[+] Starting directory bruteforce on {url}")
    with open(wordlist, 'r') as file:
        for line in file:
            dir = line.strip()
            full_url = f"{url}/{dir}"
            r = requests.get(full_url)
            if r.status_code == 200:
                print(f"[+] Found: {full_url}")

# 3. Hash Cracker
def crack_hash(hash_input, wordlist, algo="md5"):
    print(f"\n[+] Cracking {algo} hash: {hash_input}")
    with open(wordlist, 'r') as file:
        for word in file:
            word = word.strip()
            hashed = hashlib.new(algo)
            hashed.update(word.encode())
            if hashed.hexdigest() == hash_input:
                print(f"[+] Hash cracked: {word}")
                return
    print("[-] Hash not found in wordlist.")

# 4. Banner Grabber
def grab_banner(ip, port):
    print(f"\n[+] Grabbing banner from {ip}:{port}")
    try:
        sock = socket.socket()
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        print(f"[+] Banner: {banner}")
        sock.close()
    except Exception as e:
        print(f"[-] Error: {e}")

# 5. Ping Sweep
def ping_sweep(network):
    print(f"\n[+] Performing ping sweep on {network}.0/24")
    live_hosts = []
    def ping(ip):
        response = os.system(f"ping -n 1 -W 100 {ip} >nul")
        if response == 0:
            print(f"[+] Host up: {ip}")
            live_hosts.append(ip)

    with ThreadPoolExecutor(max_workers=20) as executor:
        for i in range(1, 255):
            ip = f"{network}.{i}"
            executor.submit(ping, ip)

# Main CLI
if __name__ == "__main__":
    print("=== Python Pentest Toolkit ===")
    print("1. Port Scanner")
    print("2. Dir Bruteforcer")
    print("3. Hash Cracker")
    print("4. Banner Grabber")
    print("5. Ping Sweep")

    choice = input("Select option: ")

    if choice == "1":
        host = input("Target IP: ")
        ports = list(map(int, input("Ports (comma separated): ").split(",")))
        port_scanner(host, ports)

    elif choice == "2":
        url = input("Target URL: ")
        wordlist = input("Path to wordlist: ")
        dir_bruteforce(url, wordlist)

    elif choice == "3":
        hash_input = input("Hash to crack: ")
        algo = input("Algorithm (md5/sha1) [default: md5]: ") or "md5"
        wordlist = input("Path to wordlist: ")
        crack_hash(hash_input, wordlist, algo)

    elif choice == "4":
        ip = input("Target IP: ")
        port = int(input("Port: "))
        grab_banner(ip, port)

    elif choice == "5":
        network = input("Enter base IP (e.g. 192.168.1): ")
        ping_sweep(network)

    else:
        print("[-] Invalid choice.")
