
"""
import random
from scapy.all import ICMP, IP, sr1, TCP

# Define end host and TCP port range
host = "192.168.0.1"
port_range = range(1024)

# Send SYN with random Src Port for each Dst port
for dst_port in port_range:
    src_port = random.randint(1025,65534)
    resp = sr1(
        IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
        verbose=0,
    )

    if resp is None:
        print(f"{host}:{dst_port} is filtered (silently dropped).")

    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            # Send a gratuitous RST to close the connection
            send_rst = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),timeout=1,verbose=0,)
            print(f"{host}:{dst_port} is open.")

        elif (resp.getlayer(TCP).flags == 0x14):
            print(f"{host}:{dst_port} is closed.")

    elif(resp.haslayer(ICMP)):
        if(
            int(resp.getlayer(ICMP).type) == 3 and
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
        ):
            print(f"{host}:{dst_port} is filtered (silently dropped).")
"""
from scapy.all import *
import networkx as nx
from scapy.all import ARP, Ether, srp
import matplotlib.pyplot as plt
import psutil
import time
import threading


start_time = time.time()
time_limit = 10
clients = []
counter = 0
ip_address = ""

address = []

total_traffic = {}

def capture_traffic(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        if ip not in total_traffic:
            total_traffic[ip] = 0
        total_traffic[ip] += pkt[IP].len
"""
def capture_traffic(pkt):
    if IP in pkt and pkt[IP].src in address:
        ip = pkt[IP].src
        total_traffic[ip] += pkt[IP].len


def stop_sniffing():
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread._stop()

"""

"""
def capture_traffic(pkt):
    global total_traffic
    
    if IP in pkt:
        for ip in address:
            if pkt[IP].src == ip or pkt[IP].dst == ip:
                # Packet is related to one of the IP addresses we're interested in
                elapsed_time = time.time() - start_time
                if elapsed_time <= time_limit:
                    # Only count packets captured within the time limit
                    total_traffic[ip] += pkt[IP].len
                else:
                    # Stop capturing packets after time limit is reached
                    sniff(prn=lambda x: None, filter="", store=0)

"""

"""

def capture_traffic(pkt, address):
    if IP in pkt and (pkt[IP].src in address or pkt[IP].dst in address):
        # Packet is related to one of the IP addresses we're interested in
        if pkt[IP].src in address:
            print(f"{pkt[IP].src} sent {pkt[IP].len} bytes")
        else:
            print(f"{pkt[IP].dst} received {pkt[IP].len} bytes")
"""

G = nx.Graph()
G.add_node("The Internet")
DeafultGateWay = ""

target_ip = "192.168.0.0/24"
# IP Address for the destination
# create ARP packet
arp = ARP(pdst=target_ip)
# create the Ether broadcast packet
# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
# stack them
packet = ether/arp

#print(packet)

result = srp(packet, timeout=3, verbose=0)[0]

print(result)


# a list of clients, we will fill this in the upcoming loop


for sent, received in result:
    # for each response, append ip and mac address to `clients` list
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    if (counter == 0):
        DeafultGateWay = received.psrc
        address.append(received.psrc)
        G.add_edge("The Internet",received.psrc)
        counter = counter + 1


    G.add_node(received.psrc)
    if(DeafultGateWay != received.psrc):
        G.add_edge(DeafultGateWay,received.psrc)
        address.append(received.psrc)
        total_traffic[received.psrc] = 0
    
    #Get_Trafic(received.psrc)
"""
# Start a new thread to handle the timer
timer_thread = threading.Thread(target=stop_sniffing)
timer_thread.start()

# Start sniffing for traffic
sniff_thread = threading.Thread(target=sniff, kwargs={"prn": capture_traffic, "filter": "ip"})
sniff_thread.start()

# Wait for the sniffing thread to finish
sniff_thread.join()

# Print total traffic for each IP address
for ip in address:
    print(f"Total traffic for {ip}: {total_traffic[ip]} bytes")
"""

sniff(prn=capture_traffic, filter="ip", timeout= time_limit)
for ip in address:
    print(f"Total traffic for {ip} in the last {time_limit} seconds: {total_traffic[ip]/1024} Mega bytes")
#sniff(prn=lambda pkt: capture_traffic(pkt, address), filter="ip")



# print clients
print("\n")
print("Available devices in the network:")
print("IP" + " "*18+"MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))


print("\n The graph is")
print(G.nodes())
print("\n The graph is")

pos = nx.circular_layout(G)  # Define the position of the nodes using the circular layout algorithm
nx.draw_networkx_nodes(G, pos, node_color='r', node_size=500)  # Draw the nodes
nx.draw_networkx_edges(G, pos, edge_color='b', width=4)  # Draw the edges
nx.draw_networkx_labels(G, pos, font_size=16, font_family='sans-serif')  # Draw the node labels

# Show the graph
plt.axis('off')
plt.show()

#nx.draw(G)