import scapy.all as scapy
import requests
import nmap
import os

subnet = "192.168.1.0/24"

def get_device_type(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Неизвестное устройство"
    except requests.RequestException:
        return "Неизвестное устройство"

def is_device_online(ip):
    os.system(f"ping -n 1 {ip} > nul")
    return True

def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '80,443,22,21', timeout=5)
        open_ports = []
        for proto in nm[ip].all_protocols():
            protocol_name = 'TCP' if proto == 'tcp' else 'UDP' if proto == 'udp' else 'Другой'
            ports = nm[ip][proto].keys()
            for port in ports:
                open_ports.append(f"{port} ({protocol_name})")
        return open_ports
    except Exception:
        return []

def scan_network(subnet):
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    for element in answered_list:
        device_info = {}
        device_info['IP'] = element[1].psrc
        device_info['MAC'] = element[1].hwsrc
        device_info['Type'] = get_device_type(element[1].hwsrc)
        
        if is_device_online(device_info['IP']):
            device_info['Open Ports'] = scan_ports(device_info['IP'])
        else:
            device_info['Open Ports'] = "Устройство не доступно"

        print(f"IP: {device_info['IP']}, MAC: {device_info['MAC']}, Тип: {device_info['Type']}, Открытые порты: {device_info['Open Ports']}")

def main():
    scan_network(subnet)  

if __name__ == "__main__":
    main()

