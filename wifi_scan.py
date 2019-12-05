
import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

print("IP"+"\t\t\t"+"MAC")
for i in range(0,256):
    curr_ip = "192.168.1."+str(i)
    scan_result = scan(curr_ip)
    if scan_result != []:
        print(scan_result[0]['ip']+"\t\t"+scan_result[0]['mac'])