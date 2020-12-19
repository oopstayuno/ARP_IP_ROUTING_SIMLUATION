# This is Node A
import socket
import json
import time

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

# IP and MAC Address
IP_Addr = "192.168.1.1"
MAC_Addr = "45:D4:01:25:BD:21"
SUBTNET_MASK = "255.255.255.128"
SERVER = socket.gethostbyname("localhost")

print("\n\t\tNODE A")
print("IP ADDRESS: {}\nMAC ADDRESS: {}\nSUBNET MASK: {}\n\n".format(IP_Addr, MAC_Addr, SUBTNET_MASK))

# ARP CACHE with IP: MAC value
ARP_CACHE = {}

# ROUTING TABLE for A
ROUTING_TABLE = {
    'default': {
        "Gateway": "192.168.1.254",
        "Netmask": "255.255.255.0",
        "Device": "Router 1"
    }
}


# A function to print the ROUTING TABLE
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


# Display Packet format
def displayPACKETS(message):

    if(message['type'] == 'ARP_REPLY'):
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


# To check if the packets are in the same network/subnet
def checkSubnet(ipaddr1, ipaddr2):

    ip1List = ipaddr1.split(".")
    ip2List = ipaddr2.split(".")
    subnetList = SUBTNET_MASK.split(".")

    ip1 = ""
    ip2 = ""

    for i in range(0, len(ip1List)):
        ip1 = ip1 + str((int(ip1List[i]) & int(subnetList[i]))) + "."
        ip2 = ip2 + str((int(ip2List[i]) & int(subnetList[i]))) + "."

    if(ip1[:-1] == ip2[:-1]):
        return True
    else:
        return False


# handle_message() - Function to handle all different types of messages
def handle_message(message, conn):

    # check for message type
    if(message['type'] == "DISCONNECT"):
        conn.close()
    if(message['type'] == "NEW-CONNECTION"):
        # print(message)

        # will check if the source IP address is in the same network
        # if yes, the gateway is on-link
        # else will enter the corresponding gateway address
        if(checkSubnet(IP_Addr, message['sourceIPAddr'])) == True:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']]['Gateway'] = "On-link"
            ROUTING_TABLE[message['sourceIPAddr']]['Netmask'] = SUBTNET_MASK
            ROUTING_TABLE[message['sourceIPAddr']]['Device'] = message['nodeName']
            ROUTING_TABLE[message['sourceIPAddr']]['SOCKET'] = conn

            if(message['sourceIPAddr'] != IP_Addr):

                # print("\nsending message: ", message)
                ROUTING_TABLE['default']['SOCKET'].send(str(message).encode('utf-8'))

                # print("I got the reply")
                msgConnReply = ROUTING_TABLE['default']['SOCKET'].recv(2048).decode('utf-8')

                # print("This message is: ", msgConnReply)
                conn.send(msgConnReply.encode('utf-8'))
        else:
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']]['Gateway'] = message['sourceIPAddr']
            ROUTING_TABLE[message['sourceIPAddr']]['Netmask'] = SUBTNET_MASK
            ROUTING_TABLE[message['sourceIPAddr']]['Device'] = message['nodeName']
        printRoutingTable()
    # if the message type is TCP
    if(message['type'] == 'TCP'):
        print("\n**** RECEIVED MESSAGE PACKET ****")
        displayPACKETS(message)
        print()

# PACKET FRAME STRUCTURE
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
newConnectionMessage['destinationIP'] = '192.168.1.254'
newConnectionMessage['destinationMAC'] = '00:50:57:68:AB:21'
newConnectionMessage['Netmask'] = SUBTNET_MASK
ROUTING_TABLE['default']['SOCKET'].send(str(newConnectionMessage).encode('utf-8'))
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

    print("BROADCASTING ARP REQUEST with MAC ADDRESS 00:00:00:00:00:00")

    count = 1

    validARP_REPLY = {}

    while count:

        # send to node B
        print("**** SENDING ARP REQUEST to NODE B ****")
        nodeB.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeB.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print("This is what I received: ", msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeB,
                "TYPE": "dynamic",
                "time": time.time()
            }
            # break
        else:
            # print("This is not available: ", msgReceived)
            pass

        # send to node C
        print("**** SENDING ARP REQUEST to NODE C ****")
        nodeC.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeC.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print(msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeC,
                "TYPE": "dynamic",
                "time": time.time()
            }
            # break
        else:
            # print("This is not available: ", msgReceived)
            pass

        # send to node D
        print("**** SENDING ARP REQUEST to NODE D ****")
        nodeD.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeD.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print(msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeD,
                "TYPE": "dynamic",
                "time": time.time()
            }

            # break
        else:
            # print(msgReceived)
            pass

        # send to node E
        print("**** SENDING ARP REQUEST to NODE E ****")
        nodeE.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = nodeE.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print(msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": nodeE,
                "TYPE": "dynamic",
                "time": time.time()
            }

            # break
        else:
            # print(msgReceived)
            pass

        # send to Default Router
        print("**** SENDING ARP REQUEST to DEFAULT ROUTER ****")
        defaultSocket = nodeA
        defaultSocket.send(str(arpRequestFrame).encode('utf-8'))
        msgReceived = defaultSocket.recv(2048).decode('utf-8')
        msgReceived = msgReceived.replace('\'', '"')
        arpReply = json.loads(msgReceived)
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):
            # print(msgReceived)
            validARP_REPLY = arpReply
            ARP_CACHE[targetIPAddress] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": defaultSocket,
                "TYPE": "dynamic",
                "time": time.time()
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
        print("MAC ADDRESS of {} NOT PRESENT in ARP CACHE".format(msgPacket['destinationIP']))
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


def sendPacketsInDirectForwarding(msgPacket):

    printRoutingTable()
    print("**** FORWARDING TO DEFAULT ROUTER ****")
    msgPacket["destinatonMAC"] = "00:00:00:00:00:00"
    displayPACKETS(msgPacket)

    message = str(msgPacket).encode('utf-8')
    defaultRouterSocket = ROUTING_TABLE['default']['SOCKET']
    defaultRouterSocket.send(message)
    replyMsg = defaultRouterSocket.recv(2048).decode('utf-8')
    replyMsg = replyMsg.replace('\'', '"')
    replyMsg = json.loads(replyMsg)
    handle_message(replyMsg, defaultRouterSocket)


while True:

    print()
    print("#"*80)

    query = "Choose: \n1. Send a Packet \n2. Send a ping \n=> "
    optionSelected = int(input(query))

    print(optionSelected)
    if(optionSelected == 1):

        query = "\nEnter Destination IP Address \n=> "
        destinationIP = input(query)
        message = input('Enter the Message: ')

        sendMessageFrame = PACKET

        sendMessageFrame['type'] = 'TCP'
        sendMessageFrame['destinationIP'] = destinationIP
        sendMessageFrame['message'] = message
        sendMessageFrame['messageLength'] = len(message)

        if(checkSubnet(IP_Addr, destinationIP)):

            print("\n\nSince {} is in the subnet --> DIRECT FORWARDING".format(destinationIP))
            print("\n\t\tCurrent ARP CACHE")
            printARPCache()

            # if ip mac cache not present in the ARP cache then send ARP Request
            if(destinationIP not in ARP_CACHE.keys()):
                print("\nSince MAC ADDRESS of IP {} Not Present in ARP CACHE.........".format(destinationIP))
                # Will send an ARP request to find the correct MAC Address
                findMACAddressARP(destinationIP)
            else:

                if(time.time() - ARP_CACHE[destinationIP]['time'] > 15):
                    print("ARP CACHE UPDATE AFTER 15 SECONDS")

                    del ARP_CACHE[destinationIP]

                    print("\n\t\tCurrent ARP CACHE")
                    printARPCache()

                    print("\nSince MAC ADDRESS of IP {} Not Present in ARP CACHE.........".format(destinationIP))
                    # Will send an ARP request to find the correct MAC Address
                    findMACAddressARP(destinationIP)

                print("\nMAC ADDRESS of IP {} is Present in ARP CACHE.........".format(
                    destinationIP))

            # SEND THE PACKEST TO THE TARGET DESTINATION
            sendPacketsDirectForwarding(sendMessageFrame)
        else:
            print(
                "\n\nSince {} is NOT in the subnet --> INDIRECT FORWARDING".format(destinationIP))

            printARPCache()

            # if ip mac cache not present in the ARP cache then send ARP Request
            if(ROUTING_TABLE['default']['Gateway'] not in ARP_CACHE.keys()):
                print("\nSince MAC ADDRESS of IP {} Not Present in ARP CACHE.........".format(ROUTING_TABLE['default']['Gateway']))
                # Will send an ARP request to find the correct MAC Address
                findMACAddressARP(ROUTING_TABLE['default']['Gateway'])
            else:
                print("\nMAC ADDRESS of IP {} is Present in ARP CACHE.........".format(ROUTING_TABLE['default']['Gateway']))

            sendPacketsInDirectForwarding(sendMessageFrame)

            # sendPackets(str(packet))
    else:
        query = "\nEnter IP Address: \n=> "
        destinationIP = input(query)

        if(checkSubnet(IP_Addr, destinationIP)):
            printRoutingTable()

            count = 0
            print("\n\tping {}".format(destinationIP))
            while count <= 5:
                packet_ICMP = PACKET
                packet_ICMP['type'] = 'ECHO_REQUEST'
                packet_ICMP['startTime'] = time.time()
                packet_ICMP['icmp_seq'] = count

                ROUTING_TABLE[destinationIP]['SOCKET'].send(str(packet_ICMP).encode('utf-8'))

                pingReply = ROUTING_TABLE[destinationIP]['SOCKET'].recv(2048).decode('utf-8')
                pingReply = pingReply.replace('\'', '"')
                pingReply = json.loads(pingReply)

                recvTime = time.time()

                print(" 64 bytes from {}: icmp_seq= {} ttl=111 time={} ms".format(destinationIP, pingReply['icmp_seq'], (recvTime - pingReply['startTime'])))
                count = count + 1

        else:
            print("Ping to other subnet.. not possible at the moment")
    print()
    input('Press Enter to continue.............')
    print()
