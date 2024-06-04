import xml.etree.ElementTree as ET
import json
import socket
import argparse

# remove null values
def remove_none_values(data):
    return {k: v for k, v in data.items() if v is not None}

# Send data to Logstash
def send_data(data):
    clean_data = remove_none_values(data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(bytes(json.dumps(clean_data) + "\n", encoding="utf-8"))

# Process nmap Active Hosts xml output
def handle_active_hosts(root, args):
    for host in root.findall('host'):
        data = {
            "type": "active_hosts",
            "args": args,
            "ip": host.find('address[@addrtype="ipv4"]').get('addr'),
            "state": host.find('status').get('state'),
            "reason": host.find('status').get('reason')
        }
        send_data(data)

# Process nmap Active Ports xml output
def handle_active_ports(root, args):
    for host in root.findall('host'):
        ip_address = host.find('address[@addrtype="ipv4"]').get('addr')
        for port in host.findall('ports/port'):
            data = {
                "type": "active_ports",
                "args": args,
                "ip": ip_address,
                "port": port.attrib["portid"],
                "protocol": port.attrib["protocol"],
                "state": port.find('state').get('state'),
                "reason": port.find('state').get('reason')
            }
            send_data(data)

# Process nmap Active Services xml output
def handle_active_services(root, args):
    for host in root.findall('host'):
        ip_address = host.find('address[@addrtype="ipv4"]').get('addr')
        os_element = host.find('os/osmatch')
        os = os_element.get('name') if os_element is not None else None
        for port in host.findall('ports/port'):
            if port.find('state').get('state') == "open":
                service = port.find('service')
                data = {
                    "type": "active_services",
                    "args": args,
                    "ip": ip_address,
                    "os": os,
                    "port": port.attrib["portid"],
                    "protocol": port.attrib["protocol"],
                    "state": port.find('state').get('state'),
                    "reason": port.find('state').get('reason'),
                    "service_name": service.get('name') if service is not None else None,
                    "service_version": service.get('version') if service is not None else None,
                    "product": service.get('product') if service is not None else None
                }
                send_data(data)

# Process nmap NSE Vulners xml output
def handle_vulners(root, args):
    for host in root.findall('host'):
        ip_address = host.find('address[@addrtype="ipv4"]').get('addr')
        for port in host.findall('ports/port'):
            if port.find('state').get('state') == "open":
                port_id = port.attrib["portid"]
                proto = port.attrib["protocol"]
                service = port.find('service')
                svc_vers = service.get('version') if service is not None else None
                product = service.get('product') if service is not None else None
                for table in port.findall('script/table/table'):
                    data = {
                        "type": "vulners",
                        "args": args,
                        "ip": ip_address,
                        "port": port_id,
                        "protocol": proto,
                        "product": product,
                        "service_version": svc_vers,
                        "cvss": table.find('elem[@key="cvss"]').text,
                        "exploit": table.find('elem[@key="is_exploit"]').text,
                        "pack": table.find('elem[@key="type"]').text,
                        "id": table.find('elem[@key="id"]').text
                    }
                    send_data(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Nmap XML and send data to a logstash")
    parser.add_argument('type', choices=['active_hosts', 'active_ports', 'active_services', 'vulners'], help="Type of data to process")
    parser.add_argument('xml_file', help="XML file to parse")
    parser.add_argument('--host', help="Logstash host")
    parser.add_argument('--port', type=int, default=5062, help="Logstash server port")

    args = parser.parse_args()

    HOST = args.host
    PORT = args.port

    tree = ET.parse(args.xml_file)
    root = tree.getroot()

    scan_args = root.attrib["args"]

    if args.type == "active_hosts":
        handle_active_hosts(root, scan_args)
    elif args.type == "active_ports":
        handle_active_ports(root, scan_args)
    elif args.type == "active_services":
        handle_active_services(root, scan_args)
    elif args.type == "vulners":
        handle_vulners(root, scan_args)

