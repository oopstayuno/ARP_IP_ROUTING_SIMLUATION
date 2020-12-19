# This is Node C

import socket
import json

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

# IP and MAC Address
IP_Addr = "192.168.1.3"
MAC_Addr = "A5:00:A1:25:0D:2E"
SUBTNET_MASK = "255.255.255.128"
SERVER = socket.gethostbyname("localhost")

print("\n\t\tNODE C")
print("IP ADDRESS: {}\nMAC ADDRESS: {}\nSUBNET MASK: {}\n\n".format(IP_Addr, MAC_Addr, SUBTNET_MASK))

# ARP CACHE with IP: MAC value
ARP_CACHE = {

}

# ROUTING TABLE for C
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
    'nodeName': "Node C",
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

    print("")
    # check messag Type
    if message['type'] == "DISCONNECT":
        conn.close()
    if message['type'] == "ARP_REQUEST":

        print("RECEIVED {} PACKET".format(message['type']))
        displayPACKETS(message)

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
                "deviceName": "Node B",
                "type": "ARP_REPLY",
            }
        conn.send(str(arpReplyFrame).encode('utf-8'))
    if message['type'] == "TCP":

        print("RECEIVED A PACKET.....")
        displayPACKETS(message)

        replyMessage = input("Enter Message to send: ")

        replyMessageFrame = PACKET
        replyMessageFrame['destinatonMAC'] = message['sourceMAC']
        replyMessageFrame['type'] = 'TCP'
        replyMessageFrame['destinationIP'] = message['sourceIPAddr']
        replyMessageFrame['message'] = replyMessage
        replyMessageFrame['messageLength'] = len(replyMessage)

        print("\n\t\tCURRENT ARP CACHE")
        printARPCache()

        print("\nSENDING A PACKET.....")
        displayPACKETS(replyMessageFrame)

        conn.send(str(replyMessageFrame).encode('utf-8'))

    if message['type'] == 'ECHO_REQUEST':

        print("RECEIVED ICMP - ECHO REQUEST")

        pingReply = PACKET
        pingReply['type'] = 'ECHO_REPLY'
        pingReply['startTime'] = message['startTime']
        pingReply['icmp_seq'] = message['icmp_seq']

        conn.send(str(pingReply).encode('utf-8'))


# Connect to NODE A
nodeC = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
NODE_A_PORT = data['NODE_A']['PORT_NO']
NODEA_ADDR = (SERVER, NODE_A_PORT)
nodeC.connect(NODEA_ADDR)


# will send a connection message to node A
newConnectionMessage = PACKET
newConnectionMessage['type'] = 'NEW-CONNECTION'
newConnectionMessage['destinationIP'] = '192.168.1.1'
newConnectionMessage['Netmask'] = SUBTNET_MASK
nodeC.send(str(newConnectionMessage).encode('utf-8'))
newConnectionReply = nodeC.recv(2048).decode('utf-8')
print(newConnectionReply)
printRoutingTable()
print(nodeC.recv(2048).decode('utf-8'))
print()

while True:

    packetReceived = nodeC.recv(2048).decode('utf-8')
    packetReceived = packetReceived.replace('\'', '"')
    packetReceived = json.loads(packetReceived)

    handle_message(packetReceived, nodeC)
