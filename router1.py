import socket
import json
import threading
import time

# will load the port no. from JSON file
with open('./ports.json') as f:
    data = json.load(f)

# SELF ADDRESS
IP_ADDR = "192.168.1.254"
MAC_ADDR = "00:50:57:68:AB:21"
SUBNET_MASK = "255.255.255.0"

print("\n\t\tROUTER 1")
print("IP ADDRESS: {}\nMAC ADDRESS: {}\nSUBNET MASK: {}\n\n".format(IP_ADDR, MAC_ADDR, SUBNET_MASK))

SERVER = "localhost"
DISCONNECT_MESSAGE = "!DISCONNECT"
ROUTER1_PORT = data['ROUTER_1']['PORT_NO']
ROUTER1_ADDR = (SERVER, ROUTER1_PORT)
router1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router1.bind(ROUTER1_ADDR)


# ARP CACHE with IP: MAC value
ARP_CACHE = {}

# Routing Table
ROUTING_TABLE = {}

# when a message is received from any other node it will check the type of message
# Type of message: New Connection, ICMP, ARP, message

# A function to check if two IP Address are from the same network


def checkSubnet(ipaddr1, ipaddr2, subnetMask=SUBNET_MASK):

    ip1List = ipaddr1.split(".")
    ip2List = ipaddr2.split(".")
    subnetList = subnetMask.split(".")

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


def printRoutingTable():
    print("\n\n\tROUTING TABLE........")
    print("DESTINATION \tNETMASK \tGATEWAY \tDEVICE")

    for keys in ROUTING_TABLE.keys():
        if(keys == 'default'):

            print(keys + "\t\t"+ROUTING_TABLE[keys]['Netmask']+"\t"+ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])
        else:
            print(keys + "\t"+ROUTING_TABLE[keys]['Netmask']+"\t" +ROUTING_TABLE[keys]['Gateway']+" \t"+ROUTING_TABLE[keys]['Device'])

    print()


# Print ARP CACHE of ROUTER 1


def printARPCache():
    # print("\n\n\tARP  CACHE........")
    print("INTERNET ADDRESS \tPHYSICAL ADDRESS \tTYPE")

    for keys in ARP_CACHE.keys():
        print(keys + "\t\t" +ARP_CACHE[keys]['MAC_Address']+"\t"+ARP_CACHE[keys]['TYPE'])

    print()


def findNetMask(ipAddr):

    for ipAddress in ROUTING_TABLE.keys():
        if(ipAddr != ipAddress and checkSubnet(ipAddress, ipAddr)):
            print(ROUTING_TABLE[ipAddress])
            return ROUTING_TABLE[ipAddress]['Gateway']

    return ipAddr


def findNextHop(destinationIP):

    gateway = findNetMask(destinationIP)

    if(gateway in ROUTING_TABLE.keys()):
        return ROUTING_TABLE[gateway]['socket']


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
        if(message['sourceMAC'] != "00:00:00:00:00:00"):

            print("SOURCE IP ADDRESS: \t{}".format(message['sourceIP']))
            print("SOURCE MAC ADDRESS: \t{}".format(message['sourceMAC']))
            print("TARGET IP ADDRESS: \t{}".format(message['targetIP']))
            print("TARGET MAC ADDRESS: \t{}".format(message['targetMAC']))


def findMACAddressARP(targetIPAddress, netMask):

    arpRequestFrame = {
        "sourceIP": IP_ADDR,
        "sourceMAC": MAC_ADDR,
        "targetIP": targetIPAddress,
        "targetMAC": "00:00:00:00:00:00",
        "deviceName": "",
        "type": "ARP_REQUEST",
    }

    print("BROADCASTING ARP REQUEST with MAC ADDRESS 00:00:00:00:00:00")

    for ipAddress in ROUTING_TABLE.keys():

        if(checkSubnet(targetIPAddress, ipAddress, netMask)):
            print("**** SENDING ARP REQUEST to {} ****".format(ROUTING_TABLE[ipAddress]['Device']))

            socket = ROUTING_TABLE[ipAddress]['socket']
            socket.send(str(arpRequestFrame).encode('utf-8'))

        else:
            print("Not in the same subnet: ", ipAddress)

# inorder to find the network address will and with Subnet mask and hence return the result
def findNetworkAddress(ipAddress, netMask):

    ipList = ipAddress.split(".")
    subnetList = netMask.split(".")

    ip = []

    for i in range(0, len(ipList)):
        ip.append(str((int(ipList[i]) & int(subnetList[i]))))

    networkAddr = ".".join(ip)

    return networkAddr


def handle_message(message, conn):

    # check for message type
    if(message['type'] == "DISCONNECT"):
        conn.close()
    if(message['type'] == "NEW-CONNECTION"):
        # print(message)

        print("NEW CONNECTION FROM: {}".format(message['sourceIPAddr']), end=" ")

        # Will check for the packet source ip and see if it is in the same network
        # Will store the information in routing table
        # if same network the gateway is "On-link"

        if(checkSubnet(IP_ADDR, message['sourceIPAddr'])) == True:
            print("SAME NETWORK")
            ROUTING_TABLE[message['sourceIPAddr']] = {}
            ROUTING_TABLE[message['sourceIPAddr']]['Gateway'] = "On-link"
            ROUTING_TABLE[message['sourceIPAddr']]['Netmask'] = message['Netmask']
            ROUTING_TABLE[message['sourceIPAddr']]['Device'] = message['nodeName']
            ROUTING_TABLE[message['sourceIPAddr']]['socket'] = conn
        else:
            print("DIFFERENT NETWORK")

            # will find the network address by using the subnet mask
            # will forward any packet that belong to this network
            networkAddress = findNetworkAddress(message['sourceIPAddr'], message['Netmask'])

            ROUTING_TABLE[networkAddress] = {}
            ROUTING_TABLE[networkAddress]['Gateway'] = message['Gateway']
            ROUTING_TABLE[networkAddress]['Netmask'] = message['Netmask']
            ROUTING_TABLE[networkAddress]['Device'] = message['nodeName']
            ROUTING_TABLE[networkAddress]['socket'] = conn

        printRoutingTable()

        conn.send("Connected to Router 1".encode('utf-8'))

    if message['type'] == "ARP_REQUEST":

        print("RECEIVED {} PACKET".format(message['type']))
        displayPACKETS(message)

        if(message['targetIP'] == IP_ADDR):
            # will put the MAC ADDRESS and device name
            arpReplyFrame = {
                "sourceIP": IP_ADDR,
                "sourceMAC": MAC_ADDR,
                "targetIP": message['sourceIP'],
                "targetMAC": message['sourceMAC'],
                "deviceName": "Node B",
                "type": "ARP_REPLY",
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

            print("#"*80, end="\n")
        else:
            # will put the MAC ADDRESS as 00:00:00:00:00:00:00 because the IP is not correct
            arpReplyFrame = {
                "sourceIP": IP_ADDR,
                "sourceMAC": "00:00:00:00:00:00",
                "targetIP": message['sourceIP'],
                "targetMAC": message['sourceMAC'],
                "deviceName": "Node B",
                "type": "ARP_REPLY",
            }

        conn.send(str(arpReplyFrame).encode('utf-8'))

    if message['type'] == "ARP_REPLY":

        print("RECEIVED {} PACKET".format(message['type']))
        displayPACKETS(message)

        arpReply = message

        validARP_REPLY = {}
        if(arpReply['sourceMAC'] != "00:00:00:00:00:00"):

            validARP_REPLY = arpReply
            ARP_CACHE[arpReply['sourceIP']] = {
                "MAC_Address": arpReply["sourceMAC"],
                "NODE_NAME": arpReply["deviceName"],
                "NODE_SOC": ROUTING_TABLE[arpReply['sourceIP']]['socket'],
                "TYPE": "dynamic"
            }
            print("\nARP REPLY: ")
            displayPACKETS(validARP_REPLY)
            print("\n\t\tUPDATED ARP CACHE")
            printARPCache()

    if(message['type'] == "TCP"):
        print("RECEIVED A PACKET")

        displayPACKETS(message)

        # check if the node is present in the same network
        if(checkSubnet(IP_ADDR, message['destinationIP'])) == True:
            print("**** ROUTE TO CORRECT GATEWAY/DESTINATION ****")
            print(
                "**** Forward to GATEWAY: {}".format(ROUTING_TABLE[message['destinationIP']]['Gateway']))
            print("\n\t\tCurrent ARP CACHE")
            printARPCache()
            if(message['destinationIP'] not in ARP_CACHE.keys()):
                print("\nSince MAC ADDRESS of IP {} Not Present in ARP CACHE.........".format(
                    message['destinationIP']))
                # Will send an ARP request to find the correct MAC Address
                findMACAddressARP(
                    message['destinationIP'], ROUTING_TABLE[message['destinationIP']]['Netmask'])

            # will find the correct gateway. by checking the mask
            time.sleep(2)
            nextHopSoc = ARP_CACHE[message['destinationIP']]['NODE_SOC']
            nextHopSoc.send(str(message).encode('utf-8'))
        else:

            printRoutingTable()
            nextHopNetwork = ""

            for network in ROUTING_TABLE.keys():
                print(network)
                if(checkSubnet(network, message['destinationIP'], ROUTING_TABLE[network]['Netmask'])):
                    nextHopNetwork = network
                    break

            print("**** ROUTE TO CORRECT GATEWAY/DESTINATION ****")

            # print("NETWORK IN ROUTING TABLE: ", ROUTING_TABLE[nextHopNetwork])
            print(
                "**** Forward to GATEWAY: {}".format(ROUTING_TABLE[nextHopNetwork]['Gateway']))

            # will find the correct gateway. by checking the mask
            nextHopSoc = ROUTING_TABLE[nextHopNetwork]['socket']
            nextHopSoc.send(str(message).encode('utf-8'))


def handle_client(conn, addr):
    connected = True
    while connected:
        # messages received from other nodes
        msg = conn.recv(2048).decode('utf-8')
        msg = msg.replace('\'', '"')
        msgJSON = json.loads(msg)
        handle_message(msgJSON, conn)

    # conn.close()


def start():
    router1.listen()
    print(f"[LISTENING] ROUTER 1 is listening on {SERVER}\n")
    while True:
        conn, addr = router1.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


print("[STARTING] ROUTER 1 is starting...")
start()
