# This is Node C

import socket
import json

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

# IP and MAC Address
IP_Addr = "192.168.1.3"
MAC_Addr = "A5:00:A1:25:0D:2E"
SUBTNET_MASK = "255.255.255.0"
SERVER = socket.gethostbyname("localhost")

# ARP CACHE with IP: MAC value
ARP_CACHE = {

}

# ROUTING TABLE for C
ROUTING_TABLE = {
    'default': {
        "Gateway": "192.168.1.254",
        "Netmask": SUBTNET_MASK,
        "Device": "Router 1"
    },
}

PACKET = {
    'sourceIPAddr': IP_Addr,
    'sourceMAC': MAC_Addr,
    'destinationIP': "",
    'nodeName': "Node C",
    'type': ""
}


def printRoutingTable():
    print("\n\n\tROUTING TABLE........")
    print("DESTINATION \tNETMASK \tGATEWAY \tDEVICE")

    for keys in ROUTING_TABLE.keys():
        print(keys + "\t\t"+ROUTING_TABLE[keys]
              ['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])


def handle_message(message, conn):

    # check messag Type
    if message['type'] == "DISCONNECT":
        conn.close()
    if message['type'] == "ARP_REQUEST":
        print("This will handle ARP REQUEST: ", message)

        if(message['targetIP'] == IP_Addr):
            # will put the MAC ADDRESS and device name
            arpReplyFrame = {
                "sourceIP": IP_Addr,
                "sourceMAC": MAC_Addr,
                "targetIP": message['sourceIP'],
                "targetMAC": message['sourceMAC'],
                "deviceName": "Node B",
                "type": "ARP_REQUEST",
            }
        else:
            # will put the MAC ADDRESS as 00:00:00:00:00:00:00 because the IP is not correct
            arpReplyFrame = {
                "sourceIP": IP_Addr,
                "sourceMAC": "00:00:00:00:00:00",
                "targetIP": message['sourceIP'],
                "targetMAC": message['sourceMAC'],
                "deviceName": "Node B",
                "type": "ARP_REPLY",
            }
        conn.send(str(arpReplyFrame).encode('utf-8'))
    if message['type'] == "TCP":
        print("{} : {}".format(message['nodeName'], message['message']))
        replyMessage = input("Enter Reply: ")
        print(replyMessage)
        replyMessageFrame = PACKET

        replyMessageFrame['destinatonMAC'] = message['sourceMAC']
        replyMessageFrame['type'] = 'TCP'
        replyMessageFrame['destinationIP'] = message['sourceIPAddr']
        replyMessageFrame['message'] = replyMessage
        replyMessageFrame['messageLength'] = len(replyMessage)

        conn.send(str(replyMessageFrame).encode('utf-8'))


# Connect to NODE A
nodeC = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
NODE_A_PORT = data['NODE_A']['PORT_NO']
NODEA_ADDR = (SERVER, NODE_A_PORT)
nodeC.connect(NODEA_ADDR)

# # will send a connection message to node A
# newConnectionMessage = PACKET
# newConnectionMessage['type'] = 'NEW-CONNECTION'
# newConnectionMessage['destinationIP'] = '192.168.1.1'
# nodeC.send(
#     str(newConnectionMessage).encode('utf-8'))
# newConnectionReply = nodeC.recv(2048).decode('utf-8')
# print(newConnectionReply)
# printRoutingTable()

# will send a connection message to node A
newConnectionMessage = PACKET
newConnectionMessage['type'] = 'NEW-CONNECTION'
newConnectionMessage['destinationIP'] = '192.168.1.1'
nodeC.send(
    str(newConnectionMessage).encode('utf-8'))
newConnectionReply = nodeC.recv(2048).decode('utf-8')
print(newConnectionReply)
printRoutingTable()
print("\n", nodeC.recv(2048).decode('utf-8'))


while True:

    packetReceived = nodeC.recv(2048).decode('utf-8')
    packetReceived = packetReceived.replace('\'', '"')
    packetReceived = json.loads(packetReceived)

    handle_message(packetReceived, nodeC)