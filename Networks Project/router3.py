import socket
import time
import json

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)


IP_ADDR = "192.16.137.200"
MAC_ADDR = "00:BD:16:24:01"
SUBTNET_MASK = "255.255.255.0"

# ARP CACHE with IP: MAC value
ARP_CACHE = {

}

# ROUTING TABLE for F
ROUTING_TABLE = {
    '176.16.254.254': {
        "Gateway": "176.16.254.254",
        "Netmask": "255.255.0.0",
        "Device": "Router 3"
    },
}

PACKET = {
    'sourceIPAddr': IP_ADDR,
    'sourceMAC': MAC_ADDR,
    'destinationIP': "",
    'nodeName': "Router 3",
    'type': ""
}


def printARPCache():
    # print("\n\n\tARP  CACHE........")
    print("INTERNET ADDRESS \tPHYSICAL ADDRESS \tTYPE")

    for keys in ARP_CACHE.keys():
        print(keys + "\t\t" +
              ARP_CACHE[keys]['MAC_Address']+"\t"+ARP_CACHE[keys]['TYPE'])


def printRoutingTable():
    print("\n\n\tROUTING TABLE........")
    print("DESTINATION \tNETMASK \tGATEWAY \tDEVICE")

    for keys in ROUTING_TABLE.keys():
        print(keys + "\t\t"+ROUTING_TABLE[keys]
              ['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])


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

    # check messag Type
    if message['type'] == "DISCONNECT":
        conn.close()
    if message['type'] == "ARP_REQUEST":
        print("This will handle ARP REQUEST: ", message)

        if(message['targetIP'] == IP_ADDR):
            # will put the MAC ADDRESS and device name
            arpReplyFrame = {
                "sourceIP": IP_ADDR,
                "sourceMAC": MAC_ADDR,
                "targetIP": message['sourceIP'],
                "targetMAC": message['sourceMAC'],
                "deviceName": "Node B",
                "type": "ARP_REQUEST",
            }
        else:
            # will put the MAC ADDRESS as 00:00:00:00:00:00:00 because the IP is not correct
            arpReplyFrame = {
                "sourceIP": IP_ADDR,
                "sourceMAC": "00:00:00:00:00:00",
                "targetIP": message['sourceIP'],
                "targetMAC": message['sourceMAC'],
                "deviceName": "Node H",
                "type": "ARP_REPLY",
            }

        conn.send(str(arpReplyFrame).encode('utf-8'))

    if(message['type'] == "NEW-CONNECTION"):
        print("This is the message received for New Connection\n")

        for k in message.keys():
            print("{} ---- {}".format(k, message[k]))

        # will check if the source IP address is in the same network
        # if yes, the gateway is on-link
        # else will enter the corresponding gateway address
        if(checkSubnet(IP_ADDR, message['sourceIPAddr'])) == True:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']]['Gateway'] = "On-link"
            ROUTING_TABLE[message['sourceIPAddr']]['Netmask'] = SUBTNET_MASK
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Device'] = message['nodeName']
            message['Netmask'] = SUBTNET_MASK
        else:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Gateway'] = message['sourceIPAddr']
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Netmask'] = message['Netmask']
            ROUTING_TABLE[message['sourceIPAddr']
                          ]['Device'] = message['nodeName']
            message['Netmask'] = message['Netmask']
        printRoutingTable()

        # message['Gateway'] = IP_ADDR
        # router3_2.send(str(message).encode('utf-8'))
        # conn.send("Connected to Router 2......".encode('utf-8'))
        # packetReceived = router3_2.recv(2048).decode('utf-8')

    if message['type'] == "TCP":
        if(checkSubnet(message['destinationIP'], IP_ADDR) == True):
            print("In the same subnet")

            print("\t\tCurrent ARP CACHE")
            printARPCache()

            if(message['destinationIP'] not in ARP_CACHE.keys()):
                findMACAddressARP(message['destinationIP'])
                # SEND THE PACKEST TO THE TARGET DESTINATION
                sendPackets(message)

        else:
            print("Not in same subnet {} : {}".format(
                message['nodeName'], message['message']))
            # will find the correct gateway. by checking the mask
            # nextHopSoc = findNextHop(message['destinationIP'])
            # nextHopSoc.send(str(message).encode('utf-8'))


# connect to router2
router3_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ROUTER2_PORT = data['ROUTER_2']['PORT_NO']
SERVER = socket.gethostbyname("localhost")
ROUTER2_ADDR = (SERVER, ROUTER2_PORT)
router3_2.connect(ROUTER2_ADDR)

# send a packet about new connection to router1
ROUTING_TABLE['176.16.254.254']['SOCKET'] = router3_2
newConnectionMessage = PACKET
newConnectionMessage['type'] = 'NEW-CONNECTION'
newConnectionMessage['Netmask'] = SUBTNET_MASK
ROUTING_TABLE['176.16.254.254']['SOCKET'].send(
    str(newConnectionMessage).encode('utf-8'))
newConnectionReply = router3_2.recv(2048).decode('utf-8')
print(newConnectionReply)
printRoutingTable()
print(router3_2.recv(2048).decode('utf-8'))


SERVER = "localhost"
ROUTER3_PORT = data['ROUTER_3']['PORT_NO']
ROUTER3_ADDR = (SERVER, ROUTER3_PORT)
router3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router3.bind(ROUTER3_ADDR)

nodeK = None
nodeL = None
nodeM = None
nodeN = None
nodeO = None

print("Listening...........")
router3.listen()

while(nodeK == None or nodeL == None or nodeM == None or nodeN == None or nodeO == None):
    conn, addr = router3.accept()

    # when receiving a message for connection, it will update it's routing table
    # and will send the details to router1
    connMessage = conn.recv(2048).decode('utf-8')
    connMessage = connMessage.replace('\'', '"')
    connMessage = json.loads(connMessage)

    if connMessage['nodeName'] == "Node K":
        nodeK = conn
        handle_message(connMessage, nodeK)
        nodeK.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node L":
        nodeL = conn
        handle_message(connMessage, nodeL)
        nodeL.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node M":
        nodeM = conn
        handle_message(connMessage, nodeM)
        nodeM.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node N":
        nodeN = conn
        handle_message(connMessage, nodeN)
        nodeN.send("Connected....".encode('utf-8'))
    elif connMessage['nodeName'] == "Node O":
        nodeO = conn
        handle_message(connMessage, nodeO)
        nodeO.send("Connected....".encode('utf-8'))

print()


def findMACAddressARP(targetIPAddress):

    arpRequestFrame = {
        "sourceIP": IP_ADDR,
        "sourceMAC": MAC_ADDR,
        "targetIP": targetIPAddress,
        "targetMAC": "00:00:00:00:00:00",
        "deviceName": "",
        "type": "ARP_REQUEST",
    }

    # will try to re transmit ARP Request atleat twice and if not getting the MAC Address for the send IP Address then the IP NODE MUST NOT BE AVAILABLE
    count = 1

    while count:

        # send to node B
        print("SENDING ARP to NODE K")
        nodeK.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeK.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            print("This is what I received: ", msgReceived)
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeK,
                "TYPE": "dynamic"
            }
            break
        else:
            print("This is not available: ", msgReceived)

        # send to node C
        print("SENDING ARP to NODE L")
        nodeL.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeL.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            print(msgReceived)
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeL,
                "TYPE": "dynamic"
            }
            break
        else:
            print("This is not available: ", msgReceived)

        # send to node D
        print("SENDING ARP to NODE M")
        nodeM.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeM.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            print(msgReceived)
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeM,
                "TYPE": "dynamic"
            }

            break
        else:
            print(msgReceived)

        # send to node E
        print("SENDING ARP to NODE N")
        nodeN.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeN.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            print(msgReceived)
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeN,
                "TYPE": "dynamic"
            }

            break
        else:
            print(msgReceived)

        count = count - 1

    print("\t\tUPDATED ARP CACHE")
    printARPCache()
    # print("Finally DONE")


def sendPackets(msgPacket):

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


while True:
    packetReceived = router3_2.recv(2048).decode('utf-8')

    print("\tRouter 3 \nThis is packer: \n\t", packetReceived)

    packetReceived = packetReceived.replace('\'', '"')
    packetReceived = json.loads(packetReceived)

    handle_message(packetReceived, router3_2)
