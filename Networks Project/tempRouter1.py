import socket
import time
import json
import threading

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

# SELF
IP_ADDR = "192.168.1.254"
MAC_ADDR = "00:50:57:68:AB:21"
SUBTNET_MASK = "255.255.255.0"

# Connect to CENTRAL SERVER
# router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# CENTRAL_SERVER_PORT = data['CENTRAL_SERVER']['PORT_NO']
SERVER = socket.gethostbyname("localhost")
# ADDR = (SERVER, CENTRAL_SERVER_PORT)

# # Message format - shared as dictionary
# messagePacket = {'ipAddr': IP_ADDR,
#                  'macAddr': MAC_ADDR, 'msg': '', 'msgLength': 0}


# # ----------------------- INITIAL CONNECTION TO CENTAL SERVER ------------------------------ #
# message = "Connecton Request"
# messagePacket["msg"] = message
# messagePacket["msgLength"] = len(messagePacket["msg"])
# print("Connecting to CENTRAL SERVER...................")
# router.connect(ADDR)
# router.send(str(messagePacket).encode('utf-8'))  # send the initial message
# # check reply on initial message
# msgRecFromCentServer = router.recv(2048).decode('utf-8')
# print("Messsage From Central Server: {}\n".format(msgRecFromCentServer))

# ------------------------------------------------------------------------------------------- #


# ROUTER 1 CONFIGURATION: This is for listening to all 5 nodes and 2 routers that will be connected to it
ROUTER1_PORT = data['ROUTER_1']['PORT_NO']
ROUTER1_ADDR = (SERVER, ROUTER1_PORT)
router1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router1.bind(ROUTER1_ADDR)

# dictionary

socketDict = {}

# a function to handle connection communication

message = ""


# def handleCommunication(conn, addr):

#     print(f"[NEW CONNECTION] {addr} connected.")

#     global message

#     connected = True
#     while connected:
#         msg_length = conn.recv(2048).decode('utf-8')
#         if msg_length:
#             msg_length = int(msg_length)
#             msg = conn.recv(msg_length).decode('utf-8')
#             if msg == "DISCONNECT_MESSAGE":
#                 connected = False

#             message = message + msg

#             print(f"[{addr}] {msg}")
#             conn.send(message.encode('utf-8'))

#     conn.close()


def handleCommunication(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        msg_length = conn.recv(2048).decode('utf-8')

        print(f"[{addr}] {msg_length}")
        conn.send("Msg received".encode('utf-8'))

    conn.close()


def start():
    router1.listen()
    print('[LISTENING] Central Server is listening on {}..............'.format(SERVER))
    print()

    # will have to make a count if thread number is 0 then quit the loop
    while True:
        conn, addr = router1.accept()
        thread = threading.Thread(
            target=handleCommunication, args=(conn, addr))
        thread.start()
        thread.join()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


# print("[STARTING] Centeral Server is starting...")
start()
router1.shutdown(socket.SHUT_RDWR)
router1.close()
print("closed")
