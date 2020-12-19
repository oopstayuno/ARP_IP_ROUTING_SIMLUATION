import socket
import time
import json

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

# SELF ADDRESS
IP_ADDR = "176.16.254.254"
MAC_ADDR = "A0:5D:51:68:AB:2B"
SUBNET_MASK = "255.0.0.0"
SERVER = socket.gethostbyname("localhost")

print("\n\t\tROUTER 2")
print("IP ADDRESS: {}\nMAC ADDRESS: {}\nSUBNET MASK: {}\n\n".format(IP_ADDR, MAC_ADDR, SUBNET_MASK))


# packet frame format
PACKET = {
    'sourceIPAddr': IP_ADDR,
    'destinationIP': "",
    'nodeName': "Router 2",
    'type': ""
}

# ARP CACHE with IP: MAC value
ARP_CACHE = {}

# ROUTING TABLE for ROUTER 2
ROUTING_TABLE = {
    "192.168.1.254": {
        "Gateway": "192.168.1.254",
        "Netmask": "255.255.255.0",
        "Device": "Router 1"
    }
}


def printRoutingTable():
    print("\n\n\tROUTING TABLE........")
    print("DESTINATION \tNETMASK \tGATEWAY \tDEVICE")

    for keys in ROUTING_TABLE.keys():
        if(keys == 'default'):

            print(keys + "\t\t"+ROUTING_TABLE[keys]['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])
        else:
            print(keys + "\t"+ROUTING_TABLE[keys]['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])

    print()


# Print ARP CACHE of NODE A


def printARPCache():
    # print("\n\n\tARP  CACHE........")
    print("INTERNET ADDRESS \tPHYSICAL ADDRESS \tTYPE")

    for keys in ARP_CACHE.keys():
        print(keys + "\t\t" +ARP_CACHE[keys]['MAC_Address']+"\t"+ARP_CACHE[keys]['TYPE'])

    print()


def checkSubnet(ipaddr1, ipaddr2, subnetMask=SUBNET_MASK):

    print("\nComparing the destination address with the network address by subnet masking")

    ip1List = ipaddr1.split(".")
    ip2List = ipaddr2.split(".")
    subnetList = SUBNET_MASK.split(".")

    ip1 = ""
    ip2 = ""

    for i in range(0, len(ip1List)):
        ip1 = ip1 + str((int(ip1List[i]) & int(subnetList[i]))) + "."
        ip2 = ip2 + str((int(ip2List[i]) & int(subnetList[i]))) + "."

    # print("Source IP AND SUBNET MASK \n{} AND {}  : {}".format(
    #     ipaddr1, SUBNET_MASK, ip1))
    # print("Destination IP AND SUBNET MASK \n{} AND {} : {}".format(
    #     ipaddr2, SUBNET_MASK, ip2))

    if(ip1[:-1] == ip2[:-1]):
        return True
    else:
        return False



def displayPACKETS(message):

    if(message['type'] == 'TCP'):
        print("TARGET IP ADDRESS: \t{}".format(message['destinationIP']))
        print("TARGET MAC ADDRESS: \t{}".format(message['destinatonMAC']))

    elif(message['type'] == 'ARP_REQUEST'):
        print("SOURCE IP ADDRESS: \t{}".format(message['sourceIP']))
        print("SOURCE MAC ADDRESS: \t{}".format(message['sourceMAC']))
        print("TARGET IP ADDRESS: \t{}".format(message['targetIP']))
        print("TARGET MAC ADDRESS: \t{}".format(message['targetMAC']))
    elif(message['type'] == 'ARP_REPLY'):
        print("SOURCE IP ADDRESS: \t{}".format(message['sourceIP']))
        print("SOURCE MAC ADDRESS: \t{}".format(message['sourceMAC']))
        print("TARGET IP ADDRESS: \t{}".format(message['targetIP']))
        print("TARGET MAC ADDRESS: \t{}".format(message['targetMAC']))


def findMACAddressARP(targetIPAddress):

    arpRequestFrame = {
        "sourceIP": IP_ADDR,
        "sourceMAC": MAC_ADDR,
        "targetIP": targetIPAddress,
        "targetMAC": "00:00:00:00:00:00",
        "deviceName": "",
        "type": "ARP_REQUEST",
    }

    print("BROADCASTING ARP REQUEST with MAC ADDRESS 00:00:00:00:00:00")

    # will try to re transmit ARP Request atleat twice and if not getting the MAC Address for the send IP Address then the IP NODE MUST NOT BE AVAILABLE
    count = 1

    validARP_REPLY = {}

    while count:

        # send to node F
        print("**** SENDING ARP REQUEST to NODE F ****")
        nodeF.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeF.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print("This is what I received: ", msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeF,
                "TYPE": "dynamic"
            }
            # break
        else:
            # print("This is not available: ", msgReceived)
            pass

        # send to node G
        print("**** SENDING ARP REQUEST to NODE G ****")
        nodeG.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeG.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print(msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeG,
                "TYPE": "dynamic"
            }
            # break
        else:
            # print("This is not available: ", msgReceived)
            pass

        # send to node H
        print("**** SENDING ARP REQUEST to NODE H ****")
        nodeH.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeH.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print(msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeH,
                "TYPE": "dynamic"
            }

            # break
        else:
            # print(msgReceived)
            pass

        # send to node I
        print("**** SENDING ARP REQUEST to NODE I ****")
        nodeI.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeI.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print(msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeI,
                "TYPE": "dynamic"
            }

            # break
        else:
            # print(msgReceived)
            pass

        # send to node J
        print("**** SENDING ARP REQUEST to NODE J ****")
        nodeJ.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeJ.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print(msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeJ,
                "TYPE": "dynamic"
            }

            # break
        else:
            # print(msgReceived)
            pass

        count = count - 1

    print("\nARP REPLY: ")
    displayPACKETS(validARP_REPLY)
    print("\n\t\tUPDATED ARP CACHE")
    printARPCache()


def sendPacketsDirectForwarding(msgPacket):

    if(msgPacket["destinationIP"] not in ARP_CACHE.keys()):
        print("MAC ADDRESS of {} NOT PRESENT in ARP CACHE".format(
            msgPacket['destinationIP']))
        findMACAddressARP(msgPacket["destinationIP"])

    msgPacket["destinatonMAC"] = ARP_CACHE[msgPacket["destinationIP"]]["MAC_Address"]
    print("\n**** SENDING MESSAGE PACKET ****")
    displayPACKETS(msgPacket)
    message = str(msgPacket).encode('utf-8')
    destinationSocket = ARP_CACHE[msgPacket["destinationIP"]]["NODE_SOC"]
    destinationSocket.send(message)
    replyMsg = destinationSocket.recv(2048).decode('utf-8')
    replyMsg = replyMsg.replace('\'', '"')
    replyMsg = json.loads(replyMsg)
    handle_message(replyMsg, destinationSocket)


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
            ROUTING_TABLE[message['sourceIPAddr']]['Netmask'] = SUBNET_MASK
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Device'] = message['nodeName']
            message['Netmask'] = SUBNET_MASK
        else:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Gateway'] = message['sourceIPAddr']
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Netmask'] = message['Netmask']
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Device'] = message['nodeName']
            ROUTING_TABLE[message['sourceIPAddr']]['SOCKET'] = conn
            message['Netmask'] = message['Netmask']
        printRoutingTable()

        if('Router' in message['nodeName']):
            message['Gateway'] = IP_ADDR
            router2_1.send(str(message).encode('utf-8'))
            conn.send("Connected to Router 2......".encode('utf-8'))
            packetReceived = router2_1.recv(2048).decode('utf-8')
            if packetReceived == "connected........":
                pass

    if(message['type'] == 'TCP'):

        # check if the Destination IP address is in the same subnet
        if(checkSubnet(message['destinationIP'], IP_ADDR) == True):
            print("\n\nSince {} is in the subnet --> DIRECT FORWARDING".format(message['destinationIP']))
            print("\n\t\tCurrent ARP CACHE")
            printARPCache()

            # if ip mac cache not present in the ARP cache then send ARP Request
            if(message['destinationIP'] not in ARP_CACHE.keys()):
                print("\nSince MAC ADDRESS of IP {} Not Present in ARP CACHE.........".format(message['destinationIP']))
                # Will send an ARP request to find the correct MAC Address
                findMACAddressARP(message['destinationIP'])
            else:
                print("\nMAC ADDRESS of IP {} is Present in ARP CACHE.........".format(message['destinationIP']))

            # SEND THE PACKEST TO THE TARGET DESTINATION
            sendPacketsDirectForwarding(message)

        else:

            printRoutingTable()
            nextHopNetwork = ""

            for network in ROUTING_TABLE.keys():

                if(checkSubnet(network, message['destinationIP'], ROUTING_TABLE[network]['Netmask'])):
                    nextHopNetwork = network
                    break

            print("**** ROUTE TO CORRECT GATEWAY/DESTINATION ****")

            # print("NETWORK IN ROUTING TABLE: ", ROUTING_TABLE[nextHopNetwork])
            print("**** Forward to GATEWAY: {}".format(ROUTING_TABLE[nextHopNetwork]['Gateway']))
            # will find the correct gateway. by checking the mask
            nextHopSoc = ROUTING_TABLE[nextHopNetwork]['SOCKET']
            nextHopSoc.send(str(message).encode('utf-8'))

# ##################################### #


# connect to router1
router2_1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ROUTER1_PORT = data['ROUTER_1']['PORT_NO']
ROUTER1_ADDR = (SERVER, ROUTER1_PORT)
router2_1.connect(ROUTER1_ADDR)

# send a packet about new connection to router1
ROUTING_TABLE['192.168.1.254']['SOCKET'] = router2_1
newConnectionMessage = PACKET
newConnectionMessage['type'] = 'NEW-CONNECTION'
newConnectionMessage['destinationIP'] = '192.168.1.254'
newConnectionMessage['destinationMAC'] = '00:50:57:68:AB:21'
newConnectionMessage['Netmask'] = SUBNET_MASK
newConnectionMessage['Gateway'] = IP_ADDR
ROUTING_TABLE['192.168.1.254']['SOCKET'].send(str(newConnectionMessage).encode('utf-8'))
newConnectionReply = router2_1.recv(2048).decode('utf-8')
print(newConnectionReply)
printRoutingTable()

router2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ROUTER2_PORT = data['ROUTER_2']['PORT_NO']
ROUTER2_ADDR = (SERVER, ROUTER2_PORT)
router2.bind(ROUTER2_ADDR)


nodeF = None
nodeG = None
nodeH = None
nodeI = None
nodeJ = None

router2.listen()

while(nodeF == None or nodeG == None or nodeH == None or nodeI == None or nodeJ == None):
    conn, addr = router2.accept()

    # when receiving a message for connection, it will update it's routing table
    # and will send the details to router1
    connMessage = conn.recv(2048).decode('utf-8')
    connMessage = connMessage.replace('\'', '"')
    connMessage = json.loads(connMessage)

    if connMessage['nodeName'] == "Node F":
        nodeF = conn
        handle_message(connMessage, nodeF)
        nodeF.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node G":
        nodeG = conn
        handle_message(connMessage, nodeG)
        nodeG.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node H":
        nodeH = conn
        handle_message(connMessage, nodeH)
        nodeH.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node I":
        nodeI = conn
        handle_message(connMessage, nodeI)
        nodeI.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node J":
        nodeJ = conn
        handle_message(connMessage, nodeJ)
        nodeJ.send("Connected....".encode('utf-8'))

print()

while True:
    packetReceived = router2_1.recv(2048).decode('utf-8')

    packetReceived = packetReceived.replace('\'', '"')
    packetReceived = json.loads(packetReceived)

    handle_message(packetReceived, router2_1)
