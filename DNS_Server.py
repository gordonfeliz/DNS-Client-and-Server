import sys
import socket
import binascii
import time

Root_Servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241",
                "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
                "202.12.27.33"]
cache = []

def createQuery(domain):
    # Identification didnt matter, but we wanted it to be 46290
    query = "b4d2"
    # The only bit we want to set is the RD flag, so binary: 0000000100000000 Hex: 0100
    query += "0100"
    # QDCOUNT only needs to specify a single entry in the question section
    query += "0001"
    # No Answer Upon Creation, therefore ANCOUNT is 0
    query += "0000"
    # No name server resource records in authority records upon creation, NSCOUNT is 0
    query += "0000"
    # No resource records in additional records section upon creation, ARCOUNT is 0
    query += "0000"

    # splits up domain and adds it to the question
    sections = domain.split(".")
    for section in sections:
        # Get the length of the website parts around the period and converts to hex
        query += "{:02x}".format(len(section))
        for char in section:
            # Goes through every character in the domain and gets its hex value
            query += format(ord(char), "x")

    # breakpoint: Indicates domain is done
    query += "00"
    # Setting QTYPE to 0001 establishes that we want a host address
    query += "0001"
    # We want internet for QCLASS, so it is 0x0001
    query += "0001"

    # Note: Besides the domain section, most of the query could have been combined
    # and completely avoided using the += operation, but it was done this way
    # to better understand how each section of the query worked
    return query

def DNSRequest_Root(query):
    # Sets up UDP connection to Root DNS Server
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    query = binascii.unhexlify(query)

    for x in Root_Servers:
        address = (x, 53)
        clientSocket.sendto(query, address)
        clientSocket.settimeout(10.0)
        try:
            response = clientSocket.recvfrom(1024)
        except:
            continue
        if response is not None:
            clientSocket.close()
            print("Root server IP Address: " + x)
            return binascii.hexlify(response[0]).decode("utf-8")

def DNSRequest(query, IP):
    # Sets up UDP connection to DNS Server
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    query = binascii.unhexlify(query)

    address = (IP, 53)
    clientSocket.sendto(query, address)
    clientSocket.settimeout(10.0)
    try:
        response = clientSocket.recvfrom(1024)
    except:
        exit(1)
    if response is not None:
        clientSocket.close()
        return binascii.hexlify(response[0]).decode("utf-8")

def readResponse(response, query):
    # Initially had a for loop that went for as many answers as there were, however
    # this was shown to be buggy as sometimes one of the answer counts would bug and
    # claim to have less answers then there were, resulting in no IP Address given. To
    # fix this, we replaced the for loop with a while loop and disregarded ANCOUNT, NSCOUNT,
    # and ARCOUNT altogether
    response = response[len(query):]

    while(1):
        Type = response[4:8]
        TTL = int(response[12:20], 16)
        RDLength = int(response[20:24], 16)
        RData = response[24:24 + RDLength * 2]
        delete = response[0:24 + RDLength * 2]

        # Our Response was an IP Address
        if Type == "0001":
            x = lambda hx: int(hx, 16)
            IPDecoded = str(x(RData[0:2])) + "." + str(x(RData[2:4])) + "." + str(x(RData[4:6])) + "." \
                        + str(x(RData[6:8]))
            IP_array = [str(IPDecoded), str(TTL)]
            return IP_array
        # Alas, we must sort through the junk answers
        response = response[len(delete):]

def TCP_Connection(domain, IP):
    # Sets up TCP connection to DNS Server
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    address = (IP, 80)
    clientSocket.connect(address)
    request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % domain
    clientSocket.send(request.encode())
    response = clientSocket.recv(4096)
    clientSocket.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = "tmz.com"

    print("Domain: %s" % domain)
    query = createQuery(domain)
    response = DNSRequest_Root(query)
    IP = readResponse(response, query)
    print("TLD Server IP Address: " + IP[0])
    response = DNSRequest(query, IP[0])
    IP = readResponse(response, query)
    print("Authoritative server IP address: " + IP[0])
    response = DNSRequest(query, IP[0])
    IP = readResponse(response, query)

    # Sets up cache process
    begin = time.time()
    IP.append(domain)
    cache.append(IP)

    # TCP Connection for HTTP
    print("HTTP Server IP address: " + IP[0])
    TCP_Connection(domain, IP[0])

    # Doesn't matter what you put, so long as you put something as the second argument it will test the cache
    if len(sys.argv) > 2:
        seventy = 70
        domains = ["youtube.com", "facebook.com", "tmz.com", "nytimes.com", "cnn.com"]
        count = 0
        end = time.time()
        in_cache = False
        while (int(end - begin) < seventy):
            in_cache = False
            if count > 4:
                count = 0
            print("Current Domain: " + domains[count])
            for dom in cache:
                time.sleep(1)
                end = time.time()
                if dom[2] == domains[count]:
                    if(int(end - begin) > int(dom[1])):
                        cache.remove(dom)
                        break
                    else:
                        in_cache = True
                        count += 1
                        break
            if in_cache == True:
                end = time.time()
                print("Seconds Passed Since in cache: " + str(end - begin))
                continue
            print("Domain " + domains[count] + " Not in Cache")
            end = time.time()
            print("Seconds Passed Since in cache: " + str(end-begin))
            query = createQuery(domains[count])
            response = DNSRequest_Root(query)
            RTT_begin = time.time()
            IP = readResponse(response, query)
            response = DNSRequest(query, IP[0])
            IP = readResponse(response, query)
            response = DNSRequest(query, IP[0])
            IP = readResponse(response, query)
            IP.append(domains[count])
            cache.append(IP)
            count += 1
            for dom in cache:
                print("In Cache Currently: " + dom[2])