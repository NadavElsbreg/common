import socket

__all__ = [
    name for name in globals()
    if not name.startswith("_")
    and callable(globals()[name])
]


def ping_host(host: str, count: int = 4, timeout: int = 2) -> tuple[bool, str]:
    """
    Ping a given host and return a tuple (reachable, output).

    host: hostname or IP address (string)
    count: number of ping packets to send (int, default 4)
    timeout: timeout per packet in seconds (int, default 2)

    returns: tuple (is_reachable: bool, output: str)
    """
    try:
        import platform
        import shutil
        import subprocess

        if shutil.which("ping") is None:
            return (False, "ping utility not found")

        system = platform.system().lower()
        if system == "windows":
            # -n: number of pings, -w: timeout in milliseconds
            args = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
        else:
            # -c: count, -W: timeout in seconds (may vary across platforms)
            args = ["ping", "-c", str(count), "-W", str(int(timeout)), host]

        completed = subprocess.run(args, capture_output=True, text=True, timeout=max(10, count * timeout + 5))
        output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
        return (completed.returncode == 0, output.strip())
    except subprocess.TimeoutExpired:
        return (False, "ping command timed out")
    except Exception as e:
        return (False, str(e))


    
def ping(host: str, timeout: int = 2, count: int = 1) -> bool:
    """
    Ping a host and return True if any reply is received, otherwise False.

    host: hostname or IP address (string)
    timeout: timeout per packet in seconds (default 2)
    count: number of ping packets to send (default 1)
    """
    try:
        reachable, _ = ping_host(host, count=count, timeout=timeout)
        return bool(reachable)
    except Exception:
        return False


def is_online(timeout: int = 5) -> bool:
    """
    Check if the local machine has internet connectivity.

    Tries to ping a well-known public DNS server
    """
    dns_servers =["1.1.1.1","8.8.8.8","9.9.9.9"]
    for server in dns_servers:
        if ping(server, timeout=timeout):
            return True

    
def get_local_ip() -> str:
    """
    Return the local machine's IP address as a string.

    Uses a UDP socket connection to a public address to determine the outbound
    interface IP without sending any packets.
    """
    try:
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        try:
            # Connect to a public DNS server; no data is actually sent.
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def get_public_ip(timeout: int = 5) -> str:
    """
    Return the public IP address as seen by external services.

    Tries multiple public endpoints and returns the IP as a string, or
    "0.0.0.0" on failure.
    """


    try:
        import urllib.request
        import json

        endpoints = [
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/ip",
            "https://ipinfo.io/ip",
        ]
        for url in endpoints:
            try:
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    data = resp.read().decode().strip()
                    if url.endswith("format=json"):
                        try:
                            obj = json.loads(data)
                            ip = obj.get("ip")
                        except Exception:
                            ip = data
                    else:
                        ip = data
                    if ip:
                        return ip
            except Exception:
                continue
        return "0.0.0.0"
    except Exception:
        return "0.0.0.0"


def get_mac_address() -> str:
    """
    Return the MAC address of the local machine as a string.

    Uses uuid.getnode() to obtain the hardware address and formats it as
    a colon-separated hex string. Returns "00:00:00:00:00:00" on failure.
    """
    try:
        import uuid
        mac = uuid.getnode()
        mac_str = ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
        return mac_str
    except Exception:
        return "00:00:00:00:00:00"


def _tuple_is_port_open(host: str, port: int, timeout: float = 1.0) -> tuple[bool,str]:
    if ping(host, timeout=timeout) is False:
        return False,"Host unreachable"
    try:        
        try:
            s = socket.create_connection((host, int(port)), timeout=timeout)
            s.close()
            return True, f"{port} is open"
        except Exception:
            return False , f"{port} is closed"
    except Exception:
        return False, f"{port} is closed"

def is_port_open(host: str, port: int, timeout: float = 1.0, returntuple: bool = False) -> bool | tuple[bool,str]:
    """
    Check whether a TCP port on the given host is open.

    Returns True if a TCP connection can be established within `timeout`
    seconds, otherwise False.

    host: hostname or IP address (string)
    port: port number (int)
    timeout: timeout in seconds (float, default 1.0)
    returntuple: if True, return a tuple (is_open: bool, message: str)
    """
    if returntuple:
        return _tuple_is_port_open(host, port, timeout=timeout)
    return _tuple_is_port_open(host, port, timeout=timeout)[0]


def ping_list(hosts: list[str], timeout: int = 2, count: int = 1) -> dict[str, bool]:
    """
    Ping a list of hosts and return a dictionary mapping each host to
    its reachability status (True/False).

    hosts: list of hostnames or IP addresses (list of strings)
    timeout: timeout per packet in seconds (int, default 2)
    count: number of ping packets to send (int, default 1)

    returns: dict {host: is_reachable}
    """
    results = {}
    for host in hosts:
        results[host] = ping(host, timeout=timeout, count=count)
    return results   


def free_port_scanner(host: str, start_port: int, end_port: int, timeout: float = 1.0, show_progress: bool = False) -> list[int]:
    """
    Scan a range of TCP ports on the given host and return a list of open ports.

    host: hostname or IP address (string)
    start_port: starting port number (int)
    end_port: ending port number (int)
    timeout: timeout in seconds for each port check (float, default 1.0)

    returns: list of open port numbers (list of ints)
    """
    RED = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"
    open_ports = []
    for port in range(start_port, end_port + 1):
        resalt= not is_port_open(host, port, timeout=timeout)
        if resalt:
            open_ports.append(port)
        if show_progress:
            print(f"Checked port {port} {GREEN} Free{RESET}" if resalt else f"Checked port {port} {RED} Used{RESET}")
    return open_ports


def scan_ports_list(host: str, ports: list[int], timeout: float = 1.0) -> dict[int, bool]:
    """
    Scan a list of TCP ports on the given host and return a dictionary
    mapping each port to its open status (True/False).

    host: hostname or IP address (string)
    ports: list of port numbers to check (list of ints)
    timeout: timeout in seconds for each port check (float, default 1.0)

    returns: dict {port: is_open}
    """
    results = {}
    for port in ports:
        results[port] = is_port_open(host, port, timeout=timeout)
    return results


