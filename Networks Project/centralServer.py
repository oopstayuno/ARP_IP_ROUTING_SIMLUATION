# This Server is to track all those routers and nodes that are online


import socket
import threading
import json

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

cServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER = socket.gethostbyname("localhost")
PORT = data['CENTRAL_SERVER']['PORT_NO']
ADDR = (SERVER, PORT)
cServer.bind(ADDR)

# LIST OF IP ADDRESS AND MAC ADDRESS OF ALL ROUTERS CONNECTED TO THE CENTRAL SERVER
addressTable = {"IP_ROUTER1": "192.168.1.254",
                "MAC_ROUTER1": "00:50:57:68:AB:21",
                "IP_ROUTER2": "176.16.254.254",
                "MAC_ROUTER2": "A0:5D:51:68:AB:2B",
                "IP_ROUTER3": "",
                "MAC_ROUTER3": ""}

macAddressMap = {
    "00:50:57:68:AB:21": "Router 1",
    "A0:5D:51:68:AB:2B": "Router 2"
}


def handle_client(conn, addr):
    msg_received = conn.recv(1024).decode('utf-8')
    msg_received = msg_received.replace('\'', '"')
    msg_receivedDict = json.loads(msg_received)

    if int(len(msg_received)):
        if msg_receivedDict["macAddr"] in addressTable.values():
            print('{} is connected with IP: {}'.format(
                macAddressMap[msg_receivedDict["macAddr"]], msg_receivedDict["ipAddr"]))

        conn.send("Connected".encode('utf-8'))

    conn.close()


def start():
    cServer.listen(3)
    print('[LISTENING] Central Server is listening on {}..............'.format(SERVER))
    print()

    # will have to make a count if thread number is 0 then quit the loop
    while True:
        conn, addr = cServer.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        thread.join()
        # print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


# print("[STARTING] Centeral Server is starting...")
start()
cServer.shutdown(socket.SHUT_RDWR)
cServer.close()
print("closed")
