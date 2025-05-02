import socket
import sys
import time
import os
from collections import namedtuple
import queue
from concurrent.futures import ThreadPoolExecutor
from router1_skeleton import (
    create_socket,
    read_csv,
    find_default_gateway,
    generate_forwarding_table_with_range,
    write_to_file,
    ip_to_bin,
    find_ip_range,
    bit_not,
    start_server,
    handle_client,
    ForwardingTableRow,
    ForwardingTableWithRangeRow,
    Packet,
    createForwardingTableRow,
    wait_for_client_sockets
)
from globals import *
import socket
import threading
#import helper functions from router1_skeleton.py

# Main Program

forwarding_table_csv = read_csv("./input/router_3_table.csv")
forwarding_table = [ForwardingTableRow(*row) for row in forwarding_table_csv]
default_gateway_port = find_default_gateway(forwarding_table)
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

shutdown_event = threading.Event()

packet_queue = queue.Queue()

#server ports: 8003
#client ports: d

if __name__ == "__main__":
    server1 = threading.Thread(target=start_server, args=(8003,packet_queue)).start() # port 8003 for router 2

    time.sleep(5)

    # ROUTER 3 AS A CLIENT BELOW
    client_socket_to_router_2 = create_socket(LOCALHOST, d) 

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
            write_to_file("./output/out_router_3.txt", payload)
            return

        ttl = int(ttl) - 1

        if int(ttl)<=0:
            write_to_file("./output/discarded_by_router_3.txt", str(f"{sourceIP},{destinationIP},{payload},{ttl}"))
            return

        new_packet = f"{sourceIP},{destinationIP},{payload},{ttl}"
        if nextHop == d: #exists but should never hit
            write_to_file("./output/sent_by_router_3.txt", new_packet, send_to_router=3)
            client_socket_to_router_2.sendall(new_packet.encode())
        return
    
    #wait_for_client_sockets(3)

    try:
        while True:
            try:
                packet = packet_queue.get(timeout=1) # waits up to 1 sec, raises Empty if nothing
                #time.sleep(0.5)
                print(f"raw packet in q: {packet}")
                formattedPacket = createForwardingTableRow(packet)
                process_packets(formattedPacket) #process the packet
            except queue.Empty:
                continue 
    except KeyboardInterrupt:
        print("Shutting down router 3.py...")
        shutdown_event.set()  # Signal the server to shut down
        client_socket_to_router_2.close()
        print("Router 3 shutdown complete.")
        exit(0)
