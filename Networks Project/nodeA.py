# This is Node A

import socket
import json

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

# IP and MAC Address
IP_Addr = "192.168.1.1"
MAC_Addr = "45:D4:01:25:BD:21"
SUBTNET_MASK = "255.255.255.0"
SERVER = socket.gethostbyname("localhost")

# ARP CACHE with IP: MAC value
ARP_CACHE = {}

# ROUTING TABLE for A
ROUTING_TABLE = {
    'default': {
        "Gateway": "192.168.1.254",
        "Netmask": SUBTNET_MASK,
        "Device": "Router 1"
    }
}


def printRoutingTable():
    print("\n\n\tROUTING TABLE........")
    print("DESTINATION \tNETMASK \tGATEWAY \tDEVICE")

    for keys in ROUTING_TABLE.keys():
        print(keys + "\t\t"+ROUTING_TABLE[keys]
              ['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])

# Print ARP CACHE of NODE A


def printARPCache():
    # print("\n\n\tARP  CACHE........")
    print("INTERNET ADDRESS \tPHYSICAL ADDRESS \tTYPE")

    for keys in ARP_CACHE.keys():
        print(keys + "\t\t" +
              ARP_CACHE[keys]['MAC_Address']+"\t"+ARP_CACHE[keys]['TYPE'])


def enterIntoARPCache():
    pass


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
        return True
    else:
        return False


def handle_message(message, conn):

    # check for message type
    if(message['type'] == "DISCONNECT"):
        conn.close()
    if(message['type'] == "NEW-CONNECTION"):
        print(message)

        # will check if the source IP address is in the same network
        # if yes, the gateway is on-link
        # else will enter the corresponding gateway address
        if(checkSubnet(IP_Addr, message['sourceIPAddr'])) == True:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']]['Gateway'] = "On-link"
            ROUTING_TABLE[message['sourceIPAddr']]['Netmask'] = SUBTNET_MASK
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Device'] = message['nodeName']

            if(message['sourceIPAddr'] != IP_Addr):

                print("\nsending message: ", message)
                ROUTING_TABLE['default']['SOCKET'].send(
                    str(message).encode('utf-8'))

                print("I got the reply")
                msgConnReply = ROUTING_TABLE['default']['SOCKET'].recv(
                    2048).decode('utf-8')

                print("This message is: ", msgConnReply)
                conn.send(msgConnReply.encode('utf-8'))
        else:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Gateway'] = message['sourceIPAddr']
            ROUTING_TABLE[message['sourceIPAddr']]['Netmask'] = SUBTNET_MASK
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Device'] = message['nodeName']
        printRoutingTable()
    if(message['type'] == 'TCP'):
        print("{} : {}".format(message['nodeName'], message['message']))


# PACKET = {
#     'sourceIPAddr': IP_Addr,
#     'sourceMACAddr': MAC_Addr,
#     'destinationIP': "",
#     'destinatonMAC': "",
#     'message': "",
#     'messageLength': "",
#     'nodeName': "A",
#     'type': ""
# }
# packet frame format
PACKET = {
    'sourceIPAddr': IP_Addr,
    'sourceMAC': MAC_Addr,
    'destinationIP': "",
    'nodeName': "Node A",
    'type': ""
}

# Connect to Router 1
nodeA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ROUTER1_PORT = data['ROUTER_1']['PORT_NO']
ROUTER1_ADDR = (SERVER, ROUTER1_PORT)
nodeA.connect(ROUTER1_ADDR)

ROUTING_TABLE['default']['SOCKET'] = nodeA
# send a packet abuot new connection to router1
newConnectionMessage = PACKET
newConnectionMessage['type'] = 'NEW-CONNECTION'
ROUTING_TABLE['default']['SOCKET'].send(
    str(newConnectionMessage).encode('utf-8'))
newConnectionReply = nodeA.recv(2048).decode('utf-8')
print(newConnectionReply)
printRoutingTable()

# Create a socket listen -> to connect with other nodes -> B, C, D, E (All in the same network)
nodeA_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
NODE_A_PORT = data['NODE_A']['PORT_NO']
NODEA_ADDR = (SERVER, NODE_A_PORT)
nodeA_Socket.bind(NODEA_ADDR)

nodeB = None
nodeC = None
nodeD = None
nodeE = None

nodeA_Socket.listen()


while(nodeB == None or nodeC == None or nodeD == None or nodeE == None):
    conn, addr = nodeA_Socket.accept()

    # when receiving a message for connection, it will update it's routing table
    # and will send the details to router1
    connMessage = conn.recv(2048).decode('utf-8')
    connMessage = connMessage.replace('\'', '"')
    connMessage = json.loads(connMessage)

    if connMessage['nodeName'] == "Node B":
        nodeB = conn
        handle_message(connMessage, nodeB)
        nodeB.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node C":
        nodeC = conn
        handle_message(connMessage, nodeC)
        nodeC.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node D":
        nodeD = conn
        handle_message(connMessage, nodeD)
        nodeD.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node E":
        nodeE = conn
        handle_message(connMessage, nodeE)
        nodeE.send("Connected....".encode('utf-8'))

print()


# -> Will Send and ARP Request to all the nodes in the same network


def findMACAddressARP(targetIPAddress):

    arpRequestFrame = {
        "sourceIP": IP_Addr,
        "sourceMAC": MAC_Addr,
        "targetIP": targetIPAddress,
        "targetMAC": "00:00:00:00:00:00",
        "deviceName": "",
        "type": "ARP_REQUEST",
    }

    # will try to re transmit ARP Request atleat twice and if not getting the MAC Address for the send IP Address then the IP NODE MUST NOT BE AVAILABLE
    count = 1

    while count:

        # send to node B
        print("SENDING ARP to NODE B")
        nodeB.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeB.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            print("This is what I received: ", msgReceived)
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeB,
                "TYPE": "dynamic"
            }
            break
        else:
            print("This is not available: ", msgReceived)

        # send to node C
        print("SENDING ARP to NODE C")
        nodeC.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeC.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            print(msgReceived)
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeC,
                "TYPE": "dynamic"
            }
            break
        else:
            print("This is not available: ", msgReceived)

        # send to node D
        print("SENDING ARP to NODE D")
        nodeD.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeD.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            print(msgReceived)
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeD,
                "TYPE": "dynamic"
            }

            break
        else:
            print(msgReceived)

        # send to node E
        print("SENDING ARP to NODE E")
        nodeE.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeE.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            print(msgReceived)
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeE,
                "TYPE": "dynamic"
            }

            break
        else:
            print(msgReceived)

        count = count - 1

    print("\t\tUPDATED ARP CACHE")
    printARPCache()
    # print("Finally DONE")


def sendPacketsDirectForwarding(msgPacket):

    if(msgPacket["destinationIP"] not in ARP_CACHE.keys()):
        print("NOT PRESENT")
        findMACAddressARP(msgPacket["destinationIP"])

    print("\n\n\nThis will be sent: {}\n\n".format(msgPacket))
    msgPacket["destinatonMAC"] = ARP_CACHE[msgPacket["destinationIP"]]["MAC_Address"]
    message = str(msgPacket).encode('utf-8')
    destinationSocket = ARP_CACHE[msgPacket["destinationIP"]]["NODE_SOC"]
    destinationSocket.send(message)
    replyMsg = destinationSocket.recv(2048).decode('utf-8')
    replyMsg = replyMsg.replace('\'', '"')
    replyMsg = json.loads(replyMsg)
    handle_message(replyMsg, destinationSocket)


def sendPacketsInDirectForwarding(msgPacket):
    print("\n\t\tINDIRECT FORWARDING: send to default router")
    print("This is message packet: \n")
    msgPacket["destinatonMAC"] = "00:00:00:00:00:00"
    for k in msgPacket.keys():
        print('{} --> {}'.format(k, msgPacket[k]))

    message = str(msgPacket).encode('utf-8')
    defaultRouterSocket = ROUTING_TABLE['default']['SOCKET']
    defaultRouterSocket.send(message)


while True:
    # has to send message
    query = "\n\tAvailable IP ADDRESS: \n1. 192.168.1.1 \t 2. 192.168.1.2 \n3. 192.168.1.3 \t 4. 192.168.1.4 \n5. 192.168.1.5 \t 6. 176.16.254.1 \n7. 176.16.254.2  \t 8. 176.16.254.3  \n9. 176.16.254.4 \t 10. 176.16.254.5 \n11. 192.16.137.1 \t 12. 192.16.137.2 \n13. 192.16.137.3 \t 14. 192.16.137.4 \n15. 192.16.137.5\nEnter Destination IP Adderss\n=> "
    destinationIP = input(query)
    message = input('Enter the Message: ')

    sendMessageFrame = PACKET

    sendMessageFrame['type'] = 'TCP'
    sendMessageFrame['destinationIP'] = destinationIP
    sendMessageFrame['message'] = message
    sendMessageFrame['messageLength'] = len(message)

    print("\t\tCurrent ARP CACHE")
    printARPCache()
    if(checkSubnet(IP_Addr, destinationIP)):

        print("Direct Forwarding")

        print("This is the message: ", sendMessageFrame)

        # if ip mac cache not present in the ARP cache then send ARP Request
        if(destinationIP not in ARP_CACHE.keys()):
            # Will send an ARP request to find the correct MAC Address
            findMACAddressARP(destinationIP)

        # SEND THE PACKEST TO THE TARGET DESTINATION
        sendPacketsDirectForwarding(sendMessageFrame)

        # sendPackets(str(packet))

    else:
        print("Indirect Forwarding -> Pass the packet to default router : Router 1")

        sendPacketsInDirectForwarding(sendMessageFrame)

        # sendPackets(str(packet))
    input('Press Enter to continue.............')
