
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







import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import *
import networkx as nx
from scapy.all import ARP, Ether, srp
import matplotlib.pyplot as plt
import math



#import time

time_limit = 10
clients = []
counter = 0
ip_address = ""
node_sizes = {}
node_colors = {}
edge_widths = {}
device_traffic = {}
router_ip = ""
# Set the minimum and maximum node sizes
min_node_size = 200
max_node_size = 1500


# Function to handle the click on the second screen label
def show_pie_chart():

   # Create a pie chart with device traffic
    fig, ax = plt.subplots()
    ax.pie(device_traffic.values(), labels=device_traffic.keys(), autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    ax.set_title("Device Traffic")

    # Create a new window to display the pie chart
    pie_chart_window = tk.Toplevel(window)
    pie_chart_window.title("Device Traffic")
    pie_chart_window.geometry(f"{window_width}x{window_height}")

    # Create a canvas to display the pie chart
    canvas = FigureCanvasTkAgg(fig, master=pie_chart_window)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)




def calculate_node_sizes(traffic_values, min_size, max_size):
    max_traffic_value = max(traffic_values.values())
    node_sizes = {node: min_size + (max_size - min_size) * math.sqrt(traffic / max_traffic_value)for node, traffic in traffic_values.items()}
    return node_sizes





def get_node_color(traffic):
    base_color = "#0078C8"  # Light blue base color in hexadecimal (RGB: 0, 120, 200)

    # Calculate the maximum traffic value among the devices in your network
    max_traffic = max(total_traffic[ip] for ip in address)

    # Normalize traffic to range [0, 1]
    normalized_traffic = traffic / max_traffic

    # Calculate the red component based on the normalized traffic value
    red = int((1 - normalized_traffic) * 120)  # Adjust red component

    # Combine the red, green, and blue components into a hexadecimal color code
    color_code = "#{:02X}0078".format(red)

    return color_code

# Create the main window
window = tk.Tk()
window.title("MyNet")

# Create a frame at the top for the bar
bar_frame = tk.Frame(window)
bar_frame.pack(fill=tk.X)

# Create a frame to contain the graph and pie chart
content_frame = tk.Frame(window)
content_frame.pack(fill=tk.BOTH, expand=True)

# Detect the screen size
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()

# Calculate the window size based on the screen size
window_width = int(screen_width * 0.8)
window_height = int(screen_height * 0.8)

# Set the window geometry
window.geometry(f"{window_width}x{window_height}")




# Create a figure and axes for the graph
fig, ax = plt.subplots(figsize=(window_width , window_height ))

# Create a label for displaying the current screen size
current_screen_label = tk.Label(bar_frame, text=f"Graph")
current_screen_label.pack(side=tk.LEFT, padx=10, pady=5)


# Create a label for the second screen (clickable)
second_screen_label = tk.Label(bar_frame, text="Pie Chart", cursor="hand2")
second_screen_label.pack(side=tk.LEFT, padx=10, pady=5)

# Create a frame to contain the graph
#graph_frame = tk.Frame(window)
#graph_frame.pack(fill=tk.BOTH, expand=True)

# Bind the show_pie_chart function to the click event of the second screen label
second_screen_label.bind("<Button-1>", lambda event: show_pie_chart())



address = []

total_traffic = {}

def capture_traffic(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        if ip not in total_traffic:
            total_traffic[ip] = 0
        total_traffic[ip] += pkt[IP].len

# Set up network interface in promiscuous mode to capture all packets
conf.promiscuous = True

G = nx.Graph()
#G.add_node("The Internet")

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

result = srp(packet, timeout=30, verbose=0)[0]

print(result)


# a list of clients, we will fill this in the upcoming loop


for sent, received in result:
    # for each response, append ip and mac address to `clients` list
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    if (counter == 0):
        DeafultGateWay = received.psrc
        #address.append("The Internet")
        address.append(received.psrc)
        counter = counter + 1


    G.add_node(received.psrc)
    if(DeafultGateWay != received.psrc):
        G.add_edge(DeafultGateWay,received.psrc)
        address.append(received.psrc)
        total_traffic[received.psrc] = 0
    
    #Get_Trafic(received.psrc)
interface = "Wi-Fi 3"

sniff(iface=interface, prn=capture_traffic, timeout=time_limit)

for ip in address:
    #print(f"Total traffic for {ip} in the last {time_limit} seconds: {total_traffic[ip]/1024} Mega bytes")
    device_traffic[ip] = total_traffic[ip]/1024
    if (total_traffic[ip] == 0):
        #node_sizes[ip] = 200
        node_colors[ip] = '#00F7FF'
        edge_widths[(DeafultGateWay,ip)] = 1
        #get_node_color(total_traffic[ip])
    else:
        #node_sizes[ip] = 600
        #node_colors[ip] = 'green'
        edge_widths[(DeafultGateWay,ip)] = 2
        node_colors[ip] = get_node_color(total_traffic[ip])

############################################### WIP ###########################################################
"""
for ip in total_traffic:
    if ip in address:
        continue
    else:
        total_traffic[ip]
""" 

node_sizes = calculate_node_sizes(total_traffic, min_node_size, max_node_size)
#node_colors = calculate_node_colors(total_traffic)

    


# print clients
print("\n")
print("Available devices in the network:")
print("IP" + " "*18+"MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))


print("\n The graph is")
print(G.nodes())

print(total_traffic)

# Assign node labels
labels = {node: node for node in G.nodes()}
traffic_labels = {node: f"Traffic: {total_traffic[node] / 1024} MB" for node in G.nodes()}
nx.set_node_attributes(G, labels, "label")
nx.set_node_attributes(G, traffic_labels, "traffic_label")

# Create figure and axes
fig, ax = plt.subplots(figsize=(8, 8))


# Set node positions (optional)
pos = nx.circular_layout(G)

label_positions = {node: (x, y-0.1) for node, (x, y) in pos.items()}  # Adjust the label position by subtracting a small value from the y-coordinate

#pos = nx.circular_layout(G)  # Define the position of the nodes using the circular layout algorithm
nx.draw_networkx_nodes(G, pos, node_color=[node_colors[node] for node in G.nodes()], node_size=[node_sizes[node] for node in G.nodes()])  # Draw the nodes
nx.draw_networkx_edges(G, pos, edge_color='black', width=[edge_widths[edge] for edge in G.edges()])  # Draw the edges
node_labels = nx.get_node_attributes(G, "label")
traffic_node_labels = nx.get_node_attributes(G, "traffic_label")

for node, (x, y) in pos.items():
    node_size = node_sizes[node]
    label_offset = node_size / 5000  # Adjust this factor as needed
    nx.draw_networkx_labels(G, {node: (x, y - label_offset)}, labels={node: node_labels[node]}, font_size=12,font_family='sans-serif', verticalalignment='top')
    nx.draw_networkx_labels(G, {node: (x, y + 1 * label_offset)}, labels={node: traffic_node_labels[node]},font_size=12, font_family='sans-serif', verticalalignment='bottom')


# Set plot limits and remove axes
ax.set_xlim([-1.3, 1.3])
ax.set_ylim([-1.3, 1.3])
ax.axis("off")

# Set plot background color
fig.set_facecolor("white")

# Show the graph

#plt.axis('off')
#plt.show()


# Draw the graph on the canvas
canvas = FigureCanvasTkAgg(fig, master=content_frame)
canvas.draw()
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)


# Run the Tkinter event loop
window.mainloop()
