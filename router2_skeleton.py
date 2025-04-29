import socket
import sys
import time
import os
import glob
from collections import namedtuple
import queue
from concurrent.futures import ThreadPoolExecutor

# Define a named tuple for the forwarding table
ForwardingTableRow = namedtuple("ForwardingTableRow", ["destIP", "netmask", "gateway", "interface"])
ForwardingTableWithRangeRow = namedtuple("ForwardingTableWithRangeRow", ["ip_range", "gateway", "interface"])
Packet = namedtuple("Packet", ["sourceIP", "destIP", "payload", "ttl"])
# Helper Functions

# The purpose of this function is to set up a socket connection.
def create_socket(host, port):
    # 1. Create a socket.
    # 2. Try connecting the socket to the host and port.
    # 3. Return the connected socket.
    while (True):
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.connect((host, port))
            print(f"Router on {port} ready to recieve.")
            return soc
        except ConnectionRefusedError:
            print(f"Router on {port} not ready to recieve. Retrying...")
            time.sleep(2)
            continue
        except:
            print("Unexpected Connection Error to", port)
            sys.exit()

# The purpose of this function is to read in a CSV file.
def read_csv(path):
    # 1. Open the file for reading.
    # 2. Store each line.
    # 3. Create an empty list to store each processed row.
    # 4. For each line in the file:
        # 5. split it by the delimiter,
        # 6. remove any leading or trailing spaces in each element, and
        # 7. append the resulting list to table_list.
    # 8. Close the file and return table_list.

    table_file = open(path, "r")
    table = table_file.readlines()
    table_list = []
    for line in table:
        entry = line.strip().split(",")
        entry = list((x.strip() for x in entry))
        converted_entry = ForwardingTableRow(entry[0], entry[1], entry[2], entry[3])
        table_list.append(converted_entry) #made a named tuple see line 9
    table_file.close()
    return table_list #<destIP> <subnet mask> <gateway> <interface>

# The purpose of this function is to find the default port
# when no match is found in the forwarding table for a packet's destination IP.
def find_default_gateway(table): 
    # 1. Traverse the table, row by row,
    ## for ...:
        # 2. and if the network destination of that row matches 0.0.0.0,
        ## if ...:
            # 3. then return the interface of that row.
                ## return ...
    
    #assuming table is table_list
    for x in table:
        if x.destIP == "0.0.0.0":
            return x.interface 
        
# The purpose of this function is to generate a forwarding table that includes the IP range for a given interface.
# In other words, this table will help the router answer the question:
# Given this packet's destination IP, which interface (i.e., port) should I send it out on?
def generate_forwarding_table_with_range(table):
    # 1. Create an empty list to store the new forwarding table.
    # 2. Traverse the old forwarding table, row by row,
    ## for ...:
        # 3. and process each network destination other than 0.0.0.0
        # (0.0.0.0 is only useful for finding the default port).
        ## if ...:
            # 4. Store the network destination and netmask.
            ## network_dst_string = ...
            ## netmask_string = ...
            # 5. Convert both strings into their binary representations.
            ## network_dst_bin = ...
            ## netmask_bin = ...
            # 6. Find the IP range.
            ## ip_range = ...
            # 7. Build the new row.
            ## new_row = ...
            # 8. Append the new row to new_table.
            ## new_table.append(new_row)
    # 9. Return new_table.

    new_table = []
    for x in table:
        if x.destIP != "0.0.0.0":
            netowrk_dst_string = x.destIP
            netmask_string = x.netmask
            network_dst_bin = ip_to_bin(netowrk_dst_string)
            netmask_bin = ip_to_bin(netmask_string)
            ip_range = find_ip_range(network_dst_bin, netmask_bin)
            new_table.append(ForwardingTableWithRangeRow(ip_range, x.gateway, x.interface))
    return new_table

# The purpose of this function is to convert a string IP to its binary representation.
def ip_to_bin(ip):
    # 1. Split the IP into octets.
    # 2. Create an empty string to store each binary octet.
    # 3. Traverse the IP, octet by octet,
    ## for ...:
        # 4. and convert the octet to an int,
        ## int_octet = ...
        # 5. convert the decimal int to binary,
        ## bin_octet = ...
        # 6. convert the binary to string and remove the "0b" at the beginning of the string,
        ## bin_octet_string = ...
        # 7. while the sting representation of the binary is not 8 chars long,
        # then add 0s to the beginning of the string until it is 8 chars long
        # (needs to be an octet because we're working with IP addresses).
        ## while ...:
            ## bin_octet_string = ...
        # 8. Finally, append the octet to ip_bin_string.
        ## ip_bin_string = ...
    # 9. Once the entire string version of the binary IP is created, convert it into an actual binary int.
    ## ip_int = ...
    # 10. Return the binary representation of this int.
    ip_octets = ip.split(".")
    ip_bin_string = ""

    for octet in ip_octets:
        int_octet = int(octet)
        bin_octet = bin(int_octet)
        bin_octet_string = str(bin_octet)[2:]

        while len(bin_octet_string) < 8:
            bin_octet_string = "0" + bin_octet_string
        ip_bin_string += bin_octet_string

    ip_int = int(ip_bin_string, 2)

    return ip_int

# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
def find_ip_range(network_dst, netmask):
    # 1. Perform a bitwise AND on the network destination and netmask
    # to get the minimum IP address in the range.
    ## bitwise_and = ...
    # 2. Perform a bitwise NOT on the netmask
    # to get the number of total IPs in this range.
    # Because the built-in bitwise NOT or compliment operator (~) works with signed ints,
    # we need to create our own bitwise NOT operator for our unsigned int (a netmask).
    ## compliment = ...
    ## min_ip = ...
    # 3. Add the total number of IPs to the minimum IP
    # to get the maximum IP address in the range.
    ## max_ip = ...
    # 4. Return a list containing the minimum and maximum IP in the range.
    minIP = network_dst & netmask
    range = bit_not(netmask)
    maxIP = minIP + range

    return [minIP, maxIP]

# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

# The purpose of this function is to write packets/payload to file.
def write_to_file(path, packet_to_write, send_to_router=None):
    # 1. Open the output file for appending.
    # 2. If this router is not sending, then just append the packet to the output file.
    ## if ...:
    # 3. Else if this router is sending, then append the intended recipient, along with the packet, to the output file.
    # 4. Close the output file.
    try:
        out_file = open(path, "a")
    except FileNotFoundError:
        out_file = open(path, "x")

    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    else:
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    out_file.close()


a = 8010
b = 8011
c = 8012
d = 8013
e = 8014
LOCALHOST = "127.0.0.1"
packet_queue = queue.Queue()

# Main Program

import socket
import threading

def handle_client(conn, addr):
    try:
        data = conn.recv(1024).decode()
        print(f"[{addr}] Received: {data}")
        packet_queue.put(data)
    except Exception as e:
        print(f"Error while handling {addr}: {e}")
    finally:
        conn.close() 
    

def start_server(port):
    try:
        with ThreadPoolExecutor() as executor:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(('127.0.0.1', port))
            server.listen()
            print(f"[LISTENING] Router is listening on port {port}")
            
            try:
                while not shutdown_event:  # Keep the server running indefinitely
                    conn, addr = server.accept()  # Wait for a client connection
                    print(f"[NEW CONNECTION] {addr} connected")
                    executor.submit(handle_client, conn, addr)  # Assign the client to a thread
            except KeyboardInterrupt:
                print("[SERVER SHUTDOWN] Server is shutting down.")
            finally:
                server.close() 
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.close() 
        
files = glob.glob('./output/*') #clears output
for f in files:
    os.remove(f)

forwarding_table_csv = read_csv("./input/router_1_table.csv")
forwarding_table = [ForwardingTableRow(*row) for row in forwarding_table_csv]
default_gateway_port = find_default_gateway(forwarding_table)
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

shutdown_event = threading.Event()

if __name__ == "__main__":
    server1 = threading.Thread(target=start_server, args=([a])).start() # port 8010 to router 2
    server2 = threading.Thread(target=start_server, args=([b])).start() # port 8011 to router 4

    # ROUTER 1 AS A CLIENT BELOW
    client_socket_to_router_2 = create_socket(LOCALHOST, 8002)
    client_socket_to_router_4 = create_socket(LOCALHOST, 8004)

    packets_table = read_csv("./input/packets.csv")
    packets_table = [Packet(*packet) for packet in packets_table]


    def process_packets(packet : Packet): 
        sourceIP, destinationIP, payload, ttl = packet #all remains are strings, accessed as corresponding data type"


        if int(ttl)<=0:
            write_to_file("./output/discarded_by_router_1.txt", str(f"{sourceIP},{destinationIP},{payload},{ttl}"))
            return
        ttl = int(ttl) - 1

        destinationIP_int = ip_to_bin(destinationIP)

        #find nextHop
        nextHop = None
        for x in forwarding_table_with_range:
            if destinationIP_int >= x.ip_range[0] and destinationIP_int <= x.ip_range[1]:
                nextHop = x.interface
                break
        if nextHop is None:
            nextHop = default_gateway_port
        
        if nextHop == LOCALHOST:
            write_to_file("./output/out_router_1.txt", payload)
        else:
            new_packet = f"{sourceIP},{destinationIP},{payload},{ttl}"
            write_to_file("./output/sent_by_router_1.txt", new_packet, send_to_router=nextHop)
            if nextHop == 8002:
                client_socket_to_router_2.sendall(new_packet.encode())
            elif nextHop == 8004:
                client_socket_to_router_4.sendall(new_packet.encode())
        return
    
    for packet in packets_table:
        process_packets(packet)
    
    print("Done processing packets.csv: Waiting for incoming packets...")
    try:
        while True:
            try:
                packet = packet_queue.get(timeout=1)  # waits up to 1 sec, raises Empty if nothing
                packet = generate_forwarding_table_with_range(list(packet.split(",")))
                packet = Packet(*packet)
                process_packets(packet)
            except queue.Empty:
                continue 
    except KeyboardInterrupt:
        print("Shutting down router1.py...")
        shutdown_event.set()  # Signal the server to shut down
        client_socket_to_router_2.close()
        client_socket_to_router_4.close()  # Close the client sockets
        print("Router 1 shutdown complete.")
        exit(0)

#######################################################    
    
    # 0. Remove any output files in the output directory
    # (this just prevents you from having to manually delete the output files before each run).
    # 1. Connect to the appropriate sending ports (based on the network topology diagram).
    # Router 1 acts as a client to Router 2 and Router 4
    # 2. Read in and store the forwarding table.
    # 3. Store the default gateway port.
    # 4. Generate a new forwarding table that includes the IP ranges for matching against destination IPS.
    # 5. Read in and store the packets.
  
    # 6. For each packet,
    ## for ...:
            # 7. Store the source IP, destination IP, payload, and TTL.
            ## sourceIP = ...
            ## destinationIP = ...
            ## payload = ...
            ## ttl = ...
        # 8. Decrement the TTL by 1 and construct a new packet with the new TTL.
        ## new_ttl = ...
        ## new_packet = ...
        # 9. Convert the destination IP into an integer for comparison purposes.
        ## destinationIP_bin = ...
        ## destinationIP_int = ...
        # 9. Find the appropriate sending port to forward this new packet to.
        ## ...
        # 10. If no port is found, then set the sending port to the default port.
        ## ...

    # 11. Either
    # (a) send the new packet to the appropriate port (and append it to sent_by_router_1.txt),
    # (b) append the payload to out_router_1.txt without forwarding because this router is the last hop, or
    # (c) append the new packet to discarded_by_router_1.txt and do not forward the new packet
    ## if ...:
    #    print("sending packet", new_packet, "to Router 2")
        ## ...
    ## elif ...
    #    print("sending packet", new_packet, "to Router 4")
        ## ...
    ## elif ...:
    #    print("OUT:", payload)
        ## ...
    # else:
    #   print("DISCARD:", new_packet)
        ## ...

    # Sleep for some time before sending the next packet (for debugging purposes)
