# Final_Project

This is a Python script that uses the Scapy library to capture network traffic and build a graph representation of the network topology. It also displays the network devices and their corresponding IP and MAC addresses.

Required Libraries
The following libraries are imported in the code:

scapy.all: This is the main module of the Scapy library, providing a high-level interface for packet manipulation.
networkx: This library is used to represent and manipulate graphs.
matplotlib.pyplot: This library is used for graph visualization.
time: This library provides functions for working with time.
Global Variables
start_time: It stores the start time of the script execution.
time_limit: It specifies the time limit (in seconds) for capturing network traffic.
clients: It is a list used to store information about network devices (IP and MAC addresses).
counter: It is a counter variable used to determine the default gateway.
ip_address: It stores an empty string and seems unused in the code.
address: It is a list used to store IP addresses of network devices.
total_traffic: It is a dictionary used to store the total traffic (in bytes) for each IP address.
Function: capture_traffic(pkt)
This function is a callback for the sniff function from Scapy. It is called for each captured packet and extracts information about IP addresses and their corresponding packet lengths. It updates the total_traffic dictionary.

Creating the Network Graph
G: It is an instance of the nx.Graph() class from the networkx library. It represents the network topology as a graph.
G.add_node("The Internet"): It adds a node labeled "The Internet" to the graph, representing the external network.
DefaultGateway: It is a string variable used to store the IP address of the default gateway.
Capturing ARP Traffic
target_ip: It is a string variable specifying the IP address range to scan for devices.
arp: It is an instance of the ARP class from Scapy, representing an Address Resolution Protocol packet.
ether: It is an instance of the Ether class from Scapy, representing an Ethernet frame.
packet: It is a combination of the ether and arp packets, stacked together using the / operator.
result: It is the result of sending the packet using the srp function from Scapy. It captures the responses from devices in the network.
Extracting Devices and Building the Graph
The for loop iterates over the responses stored in the result variable.
For each response, it appends the IP and MAC address to the clients list.
If counter is 0 (indicating the first response), it sets the DefaultGateway variable and adds an edge between "The Internet" node and the gateway IP address in the graph.
It adds a node for the current IP address and creates an edge between the default gateway and the current IP address in the graph.
It appends the current IP address to the address list and initializes its traffic count in the total_traffic dictionary.
Capturing Traffic and Updating Traffic Count
The sniff function from Scapy is called with the capture_traffic callback function.
The filter parameter is set to "ip" to capture only IP traffic.
The timeout parameter is set to the time_limit variable value to limit the capture duration.
Displaying Traffic Information
The for loop iterates over the IP addresses in the `
