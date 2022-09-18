import scapy.all as scapy
import pyfiglet
result = pyfiglet.figlet_format("INTRA DEF")
print(result)
def mac(ipadd):
    arp_request = scapy.ARP(pdst=ipadd)
    br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = br / arp_request
    list_1 = scapy.srp(arp_req_br, timeout=5, verbose=False)[0]
    return list_1[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        originalmac = mac(packet[scapy.ARP].psrc)
        responsemac = packet[scapy.ARP].hwsrc

        if originalmac != responsemac:
            print("[*] ALERT!! ARP spoof detected , the ARP table is being poisoned.!")
        elif originalmac==responsemac:
            print("[*] No ARP spoof attacks detected in your network..!")


print("Features available: ")
print("1.)ARP spoof detection/n2.)MAC flood detection/n3.)MITM detection/n4.)DDOS detection")

m = input("Enter an option: ")

if m == '1':
    i = input("enter the network interface: ")
    sniff(i)
elif m == '2':
    print("Sorry..! Coming soon...")
elif m == '3':
    print("Sorry..! Coming soon...")
elif m == '4':
    print("Sorry..! Coming soon...")
else:
    print("[*] Please re-run and enter a valid option..")
