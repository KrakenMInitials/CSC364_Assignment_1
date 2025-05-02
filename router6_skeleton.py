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
    createForwardingTableRow
)
from globals import *
import socket
import threading
#import helper functions from router1_skeleton.py

# Main Program

forwarding_table_csv = read_csv("./input/router_6_table.csv")
forwarding_table = [ForwardingTableRow(*row) for row in forwarding_table_csv]
default_gateway_port = find_default_gateway(forwarding_table)
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

shutdown_event = threading.Event()

packet_queue = queue.Queue()

#server ports: 8003
#client ports: d

if __name__ == "__main__":
    server1 = threading.Thread(target=start_server, args=(8006,packet_queue)).start() # port 8006 for router 4

    time.sleep(5)

    # ROUTER 3 AS A CLIENT BELOW
    client_socket_to_router_4 = create_socket(LOCALHOST, f) 

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
            write_to_file("./output/out_router_6.txt", payload)
            return

        ttl = int(ttl) - 1
        if int(ttl)<=0:
            write_to_file("./output/discarded_by_router_6.txt", str(f"{sourceIP},{destinationIP},{payload},{ttl}"))
            return

        #below varies per router

        new_packet = f"{sourceIP},{destinationIP},{payload},{ttl}"
        if int(nextHop) == e: #client to router 4 on e
            print(f"Sending packet to router 2: {new_packet}")
            write_to_file("./output/sent_by_router_6.txt", new_packet, send_to_router=4)
            client_socket_to_router_4.sendall(new_packet.encode())
        return
    
    try:
        while True:
            try:
                packet = packet_queue.get(timeout=1) # waits up to 1 sec, raises Empty if nothing
                write_to_file("./output/received_by_router_6.txt", packet)
                formattedPacket = createForwardingTableRow(packet)
                process_packets(formattedPacket) #process the packet
            except queue.Empty:
                continue 
    except KeyboardInterrupt:
        print("Shutting down router 6.py...")
        shutdown_event.set()  # Signal the server to shut down
        client_socket_to_router_4.close()
        print("Router 6 shutdown complete.")
        exit(0)
