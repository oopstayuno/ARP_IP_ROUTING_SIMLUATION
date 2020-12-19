# This is Node O

import socket
import json

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

# IP and MAC Address
IP_Addr = "192.168.1.134"
MAC_Addr = "10:14:AB:22:CC:20"
SUBNET_MASK = "255.255.255.128"

# ARP CACHE with IP: MAC value
ARP_CACHE = {}

# ROUTING TABLE for O
ROUTING_TABLE = {
    'default': {
        "Gateway": "192.168.1.254",
        "Netmask": "255.255.255.0",
        "Device": "Router 1"
    },
}

PACKET = {
    'sourceIPAddr': IP_Addr,
    'sourceMAC': MAC_Addr,
    'destinationIP': "",
    'nodeName': "Node O",
    'type': ""
}


def printARPCache():
    # print("\n\n\tARP  CACHE........")
    print("INTERNET ADDRESS \tPHYSICAL ADDRESS \tTYPE")

    for keys in ARP_CACHE.keys():
        print(keys + "\t\t" +ARP_CACHE[keys]['MAC_Address']+"\t"+ARP_CACHE[keys]['TYPE'])

    print()


def printRoutingTable():
    print("\n\n\tROUTING TABLE........")
    print("DESTINATION \tNETMASK \tGATEWAY \tDEVICE")

    for keys in ROUTING_TABLE.keys():
        if(keys == 'default'):

            print(keys + "\t\t"+ROUTING_TABLE[keys]['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])
        else:
            print(keys + "\t"+ROUTING_TABLE[keys]['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])

    print()


def displayPACKETS(message):

    if(message['type'] == 'ARP_REQUEST'):
        print("SOURCE IP ADDRESS: \t{}".format(message['sourceIP']))
        print("SOURCE MAC ADDRESS: \t{}".format(message['sourceMAC']))
        print("TARGET IP ADDRESS: \t{}".format(message['targetIP']))
        print("TARGET MAC ADDRESS: \t{}".format(message['targetMAC']))
    elif(message['type'] == 'TCP'):
        print("SOURCE IP ADDRESS: \t{}".format(message['sourceIPAddr']))
        print("SOURCE MAC ADDRESS: \t{}".format(message['sourceMAC']))
        print("TARGET IP ADDRESS: \t{}".format(message['destinationIP']))
        print("TARGET MAC ADDRESS: \t{}".format(message['destinatonMAC']))
        print("MESSAGE PAYLOAD: \t{}".format(message['message']))
        print("MESSAGE TYPE: \t\t{}".format(message['type']))

    print()


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
                "deviceName": "Node O",
                "type": "ARP_REQUEST",
            }
            print("\nSince Source IP and it's IP matches Sending:")
            print("UPDATE it's ARP CACHE")

            ARP_CACHE[message['sourceIP']] = {
                "MAC_Address": message["sourceMAC"],
                "NODE_NAME": message["deviceName"],
                "NODE_SOC": conn,
                "TYPE": "dynamic"
            }

            printARPCache()
        else:
            # will put the MAC ADDRESS as 00:00:00:00:00:00:00 because the IP is not correct
            arpReplyFrame = {
                "sourceIP": IP_Addr,
                "sourceMAC": "00:00:00:00:00:00",
                "targetIP": message['sourceIP'],
                "targetMAC": message['sourceMAC'],
                "deviceName": "Node O",
                "type": "ARP_REPLY",
            }

        conn.send(str(arpReplyFrame).encode('utf-8'))
    if message['type'] == "TCP":
        print("RECEIVED A PACKET.....")
        displayPACKETS(message)

        replyMessage = input("Enter Reply: ")

        replyMessageFrame = PACKET
        replyMessageFrame['destinatonMAC'] = message['sourceMAC']
        replyMessageFrame['type'] = 'TCP'
        replyMessageFrame['destinationIP'] = message['sourceIPAddr']
        replyMessageFrame['message'] = replyMessage
        replyMessageFrame['messageLength'] = len(replyMessage)

        print("\n\t\tCURRENT ARP CACHE")
        printARPCache()

        print("\nSENDING A PACKET.....")
        displayPACKETS(message)

        conn.send(str(replyMessageFrame).encode('utf-8'))


# Connect to Router 1
nodeO = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER = socket.gethostbyname("localhost")
ROUTER1_PORT = data['ROUTER_1']['PORT_NO']
ROUTER1_ADDR = (SERVER, ROUTER1_PORT)
nodeO.connect(ROUTER1_ADDR)

ROUTING_TABLE['default']['SOCKET'] = nodeO
# will send a connection message to router 1
newConnectionMessage = PACKET
newConnectionMessage['type'] = 'NEW-CONNECTION'
newConnectionMessage['destinationIP'] = '192.168.1.254'
newConnectionMessage['destinationMAC'] = '00:50:57:68:AB:21'
newConnectionMessage['Netmask'] = SUBNET_MASK
ROUTING_TABLE['default']['SOCKET'].send(str(newConnectionMessage).encode('utf-8'))
newConnectionReply = nodeO.recv(2048).decode('utf-8')
print(newConnectionReply)
printRoutingTable()
print()


while True:

    packetReceived = nodeO.recv(2048).decode('utf-8')

    packetReceived = packetReceived.replace('\'', '"')
    packetReceived = json.loads(packetReceived)

    handle_message(packetReceived, nodeO)
