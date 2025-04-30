import socket
import sys
import time
import os
import glob
from collections import namedtuple
import queue
from concurrent.futures import ThreadPoolExecutor
from router1_skeleton import (
    process_packets,
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
    Packet
)
from globals import *

#import helper functions from router1_skeleton.py

packet_queue = queue.Queue()

# Main Program
import socket
import threading

forwarding_table_csv = read_csv("./input/router_2_table.csv")
forwarding_table = [ForwardingTableRow(*row) for row in forwarding_table_csv]
default_gateway_port = find_default_gateway(forwarding_table)
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

shutdown_event = threading.Event()

if __name__ == "__main__":
    server1 = threading.Thread(target=start_server, args=([8002])).start() # port 8002 for router 1
    server2 = threading.Thread(target=start_server, args=([c])).start() # port c for router 4

    # ROUTER 1 AS A CLIENT BELOW
    client_socket_to_router_1 = create_socket(LOCALHOST, a) 
    client_socket_to_router_3 = create_socket(LOCALHOST, 8003)

    packets_table = read_csv("./input/packets.csv")
    packets_table = [Packet(*packet) for packet in packets_table]


    def process_packets(packet : Packet): 
        sourceIP, destinationIP, payload, ttl = packet #all remains are strings, accessed as corresponding data type"


        if int(ttl)<=0:
            write_to_file("./output/discarded_by_router_2.txt", str(f"{sourceIP},{destinationIP},{payload},{ttl}"))
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
            write_to_file("./output/out_router_2.txt", payload)
        else:
            new_packet = f"{sourceIP},{destinationIP},{payload},{ttl}"
            write_to_file("./output/sent_by_router_2.txt", new_packet, send_to_router=nextHop)
            if nextHop == 8002:
                client_socket_to_router_1.sendall(new_packet.encode())
            elif nextHop == 8004:
                client_socket_to_router_3.sendall(new_packet.encode())
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
