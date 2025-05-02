import socket
import sys
import time
import os
import glob
from collections import namedtuple
import queue
from concurrent.futures import ThreadPoolExecutor
from globals import *
import threading

# Define a named tuple for the forwarding table
ForwardingTableRow = namedtuple("ForwardingTableRow", ["destIP", "netmask", "gateway", "interface"])
ForwardingTableWithRangeRow = namedtuple("ForwardingTableWithRangeRow", ["ip_range", "gateway", "interface"])
Packet = namedtuple("Packet", ["sourceIP", "destIP", "payload", "ttl"])
# Helper Functions

def create_socket(host, port):

    while (True):
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.connect((host, port))
            print(f"[CLIENT] Client socket created on {port}.")
            socket_ready_events[port].set()
            return soc
        except ConnectionRefusedError:
            print(f"Client socket on {port} not ready to recieve. Retrying...")
            time.sleep(2)
            continue
        except:
            print("Unexpected Connection Error to", port)
            sys.exit()

def createForwardingTableRow(line : str) -> ForwardingTableRow:
    entry = line.strip().split(",")
    entry = list((x.strip() for x in entry))
    return ForwardingTableRow(entry[0], entry[1], entry[2], entry[3])

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
        proc_row = createForwardingTableRow(line)
        table_list.append(proc_row) #made a named tuple see line 9
    table_file.close()
    return table_list #<destIP> <subnet mask> <gateway> <interface>

def find_default_gateway(table): 
    for x in table:
        if x.destIP == "0.0.0.0":
            return x.interface 
        
def generate_forwarding_table_with_range(table : list[ForwardingTableRow]) -> list[ForwardingTableWithRangeRow]:
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

def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

def write_to_file(path, packet_to_write, send_to_router=None):
    # 1. Open the output file for appending.
    # 2. If this router is not sending, then just append the packet to the output file.
    ## if ...:
    # 3. Else if this router is sending, then append the intended recipient, along with the packet, to the output file.
    # 4. Close the output file.
    try:
        out_file = open(path, "a")  # Open the file in append mode
    except FileNotFoundError:
        out_file = open(path, "x")  # Create a new file if it doesn't exist

    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    else:
        out_file.write(packet_to_write + " " + "to Router " + str(send_to_router) + "\n")
    out_file.close()

def handle_client(conn, addr, queueToAddTo : queue.Queue):
    try:
        while (True):
            data = conn.recv(1024).decode()
            if not data:
                time.sleep(1)
            if shutdown_event.is_set():
                break
            print(f"[{addr}] Received: {data}")
            queueToAddTo.put(data) ##causing problem
    except Exception as e:
        print(f"UnexpectedError while handling {addr}: {e}")
    finally:
        conn.close() 
    
def start_server(port, queueToAddTo : queue.Queue):
    try:
        #print(f"[DEBUG] Creating server socket on port {port}...")
        with ThreadPoolExecutor() as executor:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reusing the port
            try:
                server.bind((LOCALHOST, port))
                #print(f"[DEBUG] Successfully bound to {LOCALHOST}:{port}")
            except Exception as e:
                #print(f"[ERROR] Failed to bind to {LOCALHOST}:{port}. Error: {e}")
                sys.exit()

            server.listen()
            print(f"[SERVER] Router is listening on {LOCALHOST}:{port}")

            try:
                while not shutdown_event.is_set():  # Keep the server running indefinitely
                    #print(f"[DEBUG] Waiting for connections on {LOCALHOST}:{port}...")
                    conn, addr = server.accept()  # Wait for a client connection
                    print(f"[SERVER] New Connection {addr} connected")
                    executor.submit(handle_client, conn, addr, queueToAddTo)  # Assign the client to a thread
            except KeyboardInterrupt:
                print("[SERVER SHUTDOWN] Server is shutting down.")
            finally:
                print("[SERVER SHUTDOWN] Closing server socket.")
                server.close() 
    except Exception as e:
        print(f"UnexpectedError: {e}")
    finally:
        server.close() 

def wait_for_client_sockets(router_num: int):
    for port in CLIENT_PORTS[router_num]:
        socket_ready_events[port].wait()
    print(f"[Router {router_num}] All connections established, starting processing.") 

#MAIN PROGRAM
packet_queue = queue.Queue()


forwarding_table_csv = read_csv("./input/router_1_table.csv")
forwarding_table = [ForwardingTableRow(*row) for row in forwarding_table_csv]
default_gateway_port = find_default_gateway(forwarding_table)
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

shutdown_event = threading.Event()

#server ports: 8010, 8011
#client ports: 8002, 8004

socket_ready_events = {
    8002: threading.Event(),
    #8004: threading.Event(),
}

if __name__ == "__main__":
    files = glob.glob('./output/*') #clears output
    for f in files:
        os.remove(f)

    server1 = threading.Thread(target=start_server, args=(a,packet_queue)).start() # port 8010 for router 2
    #server2 = threading.Thread(target=start_server, args=(b,)).start() # port 8011 for router 4

    time.sleep(5)
    # ROUTER 1 AS A CLIENT BELOW
    client_socket_to_router_2 = create_socket(LOCALHOST, 8002)
    #client_socket_to_router_4 = create_socket(LOCALHOST, 8004)

    packets_table = read_csv("./input/packets.csv")
    packets_table = [Packet(*packet) for packet in packets_table]

    def process_packets(packet : Packet): 
        sourceIP, destinationIP, payload, ttl = packet #all remains are strings, accessed as corresponding data type"

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
            return

        ttl = int(ttl) - 1

        if int(ttl)<=0:
            print("DISCARD:", packet)
            write_to_file("./output/discarded_by_router_1.txt", str(f"{sourceIP},{destinationIP},{payload},{ttl}"))
            return

        new_packet = f"{sourceIP},{destinationIP},{payload},{ttl}"
        if int(nextHop) == 8002:
            write_to_file("./output/sent_by_router_1.txt", new_packet, send_to_router=2)
            try:
                print(f"Sending packet to router 2: {new_packet}")
                client_socket_to_router_2.sendall(new_packet.encode())
            except ConnectionAbortedError as e:
                print(f"Connection was aborted: {e}")
        elif int(nextHop) == 8004:
            write_to_file("./output/sent_by_router_1.txt", new_packet, send_to_router=4)
            #client_socket_to_router_4.sendall(new_packet.encode())
        return
    
    #wait_for_client_sockets(1)

    for packet in packets_table:
        process_packets(packet)
    
    print("Done processing packets.csv: Waiting for incoming packets...")
    try:
        while True:
            try:
                packet = packet_queue.get(timeout=1) # waits up to 1 sec, raises Empty if nothing
                print(f"Running through -{packet}-")
                #time.sleep(0.5) # Sleep for a short duration to simulate processing time
                formattedPacket = createForwardingTableRow(packet)
                process_packets(formattedPacket) #process the packet
            except queue.Empty:
                print("queue emptied.")
                continue 
    except KeyboardInterrupt:
        print("Shutting down router1.py...")
        shutdown_event.set()  # Signal the server to shut down
        client_socket_to_router_2.close()
        #client_socket_to_router_4.close()  # Close the client sockets
        print("Router 1 shutdown complete.")
        exit(0)
