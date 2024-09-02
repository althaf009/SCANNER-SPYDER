import socket
import time
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

# List of common and additional ports
COMMON_PORTS = list(range(1, 1025)) + [
    3306, 5432, 1521, 27017, 3389, 445, 5900, 5985, 5986,
    8080, 8443, 10000, 8005, 8009, 1194, 1723, 1701,
    2222, 2121, 1883, 5683
]

def resolve_domain(domain):
    """Resolve the domain to an IP address."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(f"{Fore.RED}Error: Unable to resolve domain.")
        return None

def scan_port(ip, port):
    """Check if a port is open on the given IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        return port if result == 0 else None

def banner_grab(ip, port):
    """Grabs the service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode().strip()
            return banner
    except:
        return None

def check_outdated_versions(ip, open_ports):
    """Check for outdated software versions on open ports."""
    print(f"{Fore.YELLOW}Checking for outdated software versions on {ip}...")

    known_vulnerable_versions = {
        "Apache": "2.2.3",
        "nginx": "1.14.0",
        # Add more services and their known vulnerable versions here
    }

    for port in open_ports:
        banner = banner_grab(ip, port)
        if banner:
            for service, vulnerable_version in known_vulnerable_versions.items():
                if service in banner and vulnerable_version in banner:
                    print(f"{Fore.RED}[Vulnerability] {service} {vulnerable_version} is outdated on port {port}.")

    print(f"{Fore.GREEN}Outdated version check complete.")

def check_misconfigurations(domain):
    """Check for common misconfigurations."""
    print(f"{Fore.YELLOW}Checking for misconfigurations on {domain}...")

    try:
        response = requests.get(f"http://{domain}")
        headers = response.headers

        # Security headers to check
        required_headers = {
            'X-Frame-Options': "Missing X-Frame-Options header.",
            'Strict-Transport-Security': "Weak or missing Strict-Transport-Security configuration.",
            'Content-Security-Policy': "Missing Content-Security-Policy header.",
            'X-Content-Type-Options': "Missing X-Content-Type-Options header.",
            'X-Permitted-Cross-Domain-Policies': "Missing X-Permitted-Cross-Domain-Policies header.",
            'Referrer-Policy': "Missing Referrer-Policy header.",
            'X-XSS-Protection': "Missing X-XSS-Protection header.",
            'X-Download-Options': "Missing X-Download-Options header.",
            'Feature-Policy': "Missing Feature-Policy header.",
            'Expect-CT': "Missing Expect-CT header.",
            'Permissions-Policy': "Missing Permissions-Policy header.",
            'Cache-Control': "Weak or missing Cache-Control header."
        }

        for header, message in required_headers.items():
            if header not in headers:
                print(f"{Fore.RED}[Misconfiguration] {message}")

        # DMARC configuration check
        try:
            answers = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
            dmarc_record = ''.join(record.to_text() for record in answers)
            if 'v=DMARC1' in dmarc_record:
                print(f"{Fore.GREEN}[Configuration] DMARC record found and configured.")
            else:
                print(f"{Fore.RED}[Misconfiguration] DMARC record not properly configured.")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"{Fore.RED}[Misconfiguration] DMARC record not found in DNS.")

    except requests.RequestException as e:
        print(f"{Fore.RED}Error: {e}")

    print(f"{Fore.GREEN}Misconfiguration check complete.")

def scan_ports(ip):
    open_ports = []
    total_ports = len(COMMON_PORTS)
    start_time = time.time()

    print(f"Starting scan on {ip}...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in COMMON_PORTS]
        for i, future in enumerate(futures, 1):
            port = future.result()
            if port:
                open_ports.append(port)

            # Update the progress and estimated time remaining
            elapsed_time = time.time() - start_time
            percentage = (i / total_ports) * 100
            time_per_port = elapsed_time / i
            estimated_time_remaining = time_per_port * (total_ports - i)

            print(f"\r{Fore.CYAN}[{i}/{total_ports}] Ports Scanned: {percentage:.2f}% | "
                  f"Time Remaining: {estimated_time_remaining:.2f}s", end='')

    print("\n\nScan complete!\n")
    if open_ports:
        print(f"{Fore.GREEN}Open ports:")
        for port in open_ports:
            print(f"  - {port}/tcp open")
    else:
        print(f"{Fore.RED}No open ports found.")

    return open_ports

def main():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
   ____  _           _______ ____  _   _ 
  / __ \\| |         |__   __/ __ \\| \\ | |
 | |  | | | ___ _ __ _| |_ | |  | |  \\| |
 | |  | | |/ _ \\ '__| | __|| |  | | . ` |
 | |__| | |  __/ |  | | |_ | |__| | |\\  |
  \\____/|_|\\___|_|  |_|\\__(_)____/|_| \\_|

{Fore.GREEN}A Comprehensive Vulnerability Scanner
{Style.RESET_ALL}
    """

    print(banner)

    domain = input(f"{Fore.YELLOW}Enter domain to scan: {Style.RESET_ALL}")
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    ip = resolve_domain(domain)
    if not ip:
        return

    open_ports = scan_ports(ip)
    check_outdated_versions(ip, open_ports)
    check_misconfigurations(domain)

if __name__ == "__main__":
    main()

