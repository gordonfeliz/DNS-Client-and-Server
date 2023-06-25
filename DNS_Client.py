import sys
import socket
import binascii

Iran_DNS = ["91.245.229.1", "46.224.1.42", "185.161.112.34"]
USA_DNS = ["169.237.229.88", "168.62.214.68", "104.42.159.98"]
Canada_DNS = ["136.159.85.15", "184.94.80.170", "142.103.1.1"]

def createQuery(domain):
    # Identification: didnt matter, but we wanted it to be 46290
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
    query += "0001" # QTYPE
    # We want internet for QCLASS, so it is 0x0001
    query += "0001"

    # Note: Besides the domain section, most of the query could have been combined
    # and completely avoided using the += operation, but it was done this way
    # to better understand how each section of the query worked
    return query

def DNSRequest(query):
    # Sets up UDP connection to DNS Server
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    query = binascii.unhexlify(query)
    response = []

    # Iran_DNS Check
    for x in Iran_DNS:
        address = (x, 53)
        clientSocket.sendto(query, address)
        clientSocket.settimeout(10.0)
        try:
            response1 = clientSocket.recvfrom(1024)
        except:
            continue
        if response1 is not None:
            response.append(binascii.hexlify(response1[0]).decode("utf-8"))
            break

    # USA_DNS Check
    for x in USA_DNS:
        address = (x, 53)
        clientSocket.sendto(query, address)
        clientSocket.settimeout(10.0)
        try:
            response2 = clientSocket.recvfrom(1024)
        except:
            continue
        if response2 is not None:
            response.append(binascii.hexlify(response2[0]).decode("utf-8"))
            break

    # Canada_DNS Check
    for x in Canada_DNS:
        address = (x, 53)
        clientSocket.sendto(query, address)
        clientSocket.settimeout(10.0)
        try:
            response3 = clientSocket.recvfrom(1024)
        except:
            continue
        if response is not None:
            clientSocket.close()
            response.append(binascii.hexlify(response3[0]).decode("utf-8"))
            return response

def readResponse(response, query):
    # The ID, Flags, and QDCOUNT are unnecessary for finding the IP, so skip first 12 hex chars
    ANCOUNT = int(response[12:16], 16)

    # Everything after related to the query we made is also unnecessary
    response = response[len(query):]

    # It is expected that there will only be one answer, the host name, but we left this for loop intact
    # to show what it would have looked like (although it doesnt include the other COUNT types)
    # for PartB if it wasnt buggy
    for answers in range(0, ANCOUNT):
        Type_Check = response[4:8]
        IPLen = int(response[20:24], 16)
        IPEncoded = response[24:24 + IPLen * 2]

        # Double Checks that we were given an IP Address as Response
        if Type_Check == "0001":
            x = lambda hx: int(hx, 16)
            IPDecoded = str(x(IPEncoded[0:2])) + "." + str(x(IPEncoded[2:4])) + "." + str(x(IPEncoded[4:6])) + "." \
                        + str(x(IPEncoded[6:8]))
            return str(IPDecoded)

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
    response = DNSRequest(query)
    IP_Iran = readResponse(response[0], query)
    IP_USA = readResponse(response[1], query)
    IP_Canada = readResponse(response[2], query)
    print("HTTP Server IP address: " + IP_USA)
    TCP_Connection(domain, IP_USA)