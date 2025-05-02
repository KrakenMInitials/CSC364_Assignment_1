import threading

a = 8010
b = 8011
c = 8012
d = 8013
e = 8014
f = 8015
LOCALHOST = "127.0.0.1"

# Assign ports each router will connect *to*
CLIENT_PORTS = {
    1: [8002, 8004],  # Router 1 connects to Router 2 (8002) and Router 3 (8004)
    2: [a, 8003],        # Router 2 connects to Router 3 (8003)
    3: [d]             # Router 3 doesn’t connect to anyone
}

# One Event per port being connected TO (i.e., the server sockets)
socket_ready_events = {
    port: threading.Event()
    for ports in CLIENT_PORTS.values()
    for port in ports
}
