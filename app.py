import psutil
import socket
import scapy.all as scapy



def get_active_interfaces():
    """
    Returns a list of active network interfaces on the device.
    An interface is considered active if it has an assigned IP address and netmask.
    """

    interfaces = psutil.net_if_addrs()  # Get information for all interfaces
    active_interfaces = []
    for interface_name, info in interfaces.items():
        for address in info:
            # Check if it's an IPv4 address with a netmask
            if address.family == socket.AF_INET and address.netmask:
                active_interfaces.append(interface_name)
                break  # Move on to the next interface once an IP is found
    return active_interfaces

def packet_analysis(packet):
    """Analyzes a captured packet and extracts relevant information."""

    # Extract IP addresses, protocol, MAC addresses, and packet size
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    src_mac = packet.src  # MAC addresses are at the Ethernet layer
    dst_mac = packet.dst
    protocol_name = scapy.IP(proto=packet[scapy.IP].proto).name
    packet_size = len(packet)

    # Extract ports for TCP/UDP
    src_port = None
    dst_port = None
    if protocol_name == "TCP":
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
    elif protocol_name == "UDP":
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport


    # Print the information
    print(f"--" * 20)  # Optional separator
    print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
    print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}")
    print(f"Protocol: {protocol_name}")
    if src_port and dst_port:
        print(f"Source Port: {src_port}, Destination Port: {dst_port}")
    print(f"Packet Size: {packet_size} bytes")


if __name__ == "__main__":
    # Display active interfaces
    active_interfaces = get_active_interfaces()
    print("Active interfaces:")
    for i, interface in enumerate(active_interfaces):
        print(f"{i + 1}. {interface}")

    # Get user selection
    while True:
        try:
            choice = int(input("Select an interface: "))
            if 1 <= choice <= len(active_interfaces):
                selected_interface = active_interfaces[choice - 1]
                break
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Start packet capture and analysis
    print(f"\nStarting packet capture on {selected_interface}...")
    scapy.sniff(iface=selected_interface, prn=packet_analysis)
