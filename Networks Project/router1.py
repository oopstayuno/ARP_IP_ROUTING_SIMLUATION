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

SERVER = "localhost"
DISCONNECT_MESSAGE = "!DISCONNECT"
ROUTER1_PORT = data['ROUTER_1']['PORT_NO']
ROUTER1_ADDR = (SERVER, ROUTER1_PORT)
router1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router1.bind(ROUTER1_ADDR)

# Routing Table
ROUTING_TABLE = {}

# when a message is received from any other node it will check the type of message
# Type of message: New Connection, ICMP, ARP, message


def checkSubnet(ipaddr1, ipaddr2):

    print("\nComparing the destination address with the network address by subnet masking")

    ip1List = ipaddr1.split(".")
    ip2List = ipaddr2.split(".")
    subnetList = SUBTNET_MASK.split(".")

    ip1 = ""
    ip2 = ""

    for i in range(0, len(ip1List)):
        ip1 = ip1 + str((int(ip1List[i]) & int(subnetList[i]))) + "."
        ip2 = ip2 + str((int(ip2List[i]) & int(subnetList[i]))) + "."

    print("Source IP AND SUBNET MASK \n{} AND {}  : {}".format(
        ipaddr1, SUBTNET_MASK, ip1))
    print("Destination IP AND SUBNET MASK \n{} AND {} : {}".format(
        ipaddr2, SUBTNET_MASK, ip2))

    if(ip1[:-1] == ip2[:-1]):
        print("True")
        return True
    else:
        print("False")
        return False


def printRoutingTable():
    print("\n\n\tROUTING TABLE........")
    print("DESTINATION \tNETMASK \tGATEWAY \tDEVICE")

    for keys in ROUTING_TABLE.keys():
        print(keys + "\t"+ROUTING_TABLE[keys]
              ['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])


def findNetMask(ipAddr):

    print("\nThis is: ", ROUTING_TABLE)
    for ipAddress in ROUTING_TABLE.keys():
        if(ipAddr != ipAddress and checkSubnet(ipAddress, ipAddr)):
            print(ROUTING_TABLE[ipAddress])
            return ROUTING_TABLE[ipAddress]['Gateway']

    return ipAddr


def findNextHop(destinationIP):

    gateway = findNetMask(destinationIP)

    print("This is Gatewya: ", gateway)
    if(gateway in ROUTING_TABLE.keys()):
        return ROUTING_TABLE[gateway]['socket']


def handle_message(message, conn):

    # check for message type
    if(message['type'] == "DISCONNECT"):
        conn.close()
    if(message['type'] == "NEW-CONNECTION"):
        print(message)

        # will check if the source IP address is in the same network
        # if yes, the gateway is on-link
        # else will enter the corresponding gateway address
        if(checkSubnet(IP_ADDR, message['sourceIPAddr'])) == True:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']]['Gateway'] = "On-link"
            ROUTING_TABLE[message['sourceIPAddr']]['Netmask'] = SUBTNET_MASK
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Device'] = message['nodeName']
        else:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Gateway'] = message['Gateway']
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Netmask'] = message['Netmask']
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Device'] = message['nodeName']
            ROUTING_TABLE[message['sourceIPAddr']]['socket'] = conn

        printRoutingTable()

        conn.send("Connected to Router 1".encode('utf-8'))

    if(message['type'] == "TCP"):
        print("This is message sending......: ")
        for k in message.keys():
            print("{} ---> {}".format(k, message[k]))

        # will find the correct gateway. by checking the mask
        nextHopSoc = findNextHop(message['destinationIP'])
        nextHopSoc.send(str(message).encode('utf-8'))


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        # messages received from other nodes
        msg = conn.recv(2048).decode('utf-8')
        msg = msg.replace('\'', '"')
        msgJSON = json.loads(msg)
        print(f"[{addr}] {msgJSON}")
        handle_message(msgJSON, conn)

    # conn.close()


def start():
    router1.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = router1.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


print("[STARTING] server is starting...")
start()

print("Done or still going??")
