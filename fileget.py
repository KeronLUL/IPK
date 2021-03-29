import socket
import argparse
import re
import sys

def argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', help='NAMESERVER', required=True)
    parser.add_argument('-f', help='SURL', required=True)
    args = parser.parse_args()

    server = re.match(r"^fsp://", args.f)
    if not server:
        sys.exit("Invalid arguments")

    foo = args.f.split("//")
    ip = args.n.split(":")
    return ip[0], int(ip[1]), foo[1]

def NSP(host, port, server):
    message = "WHEREIS " + server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((host, port))
    sock.settimeout(5)
    sock.send(message.encode())

    data = sock.recv(1024)
    message = data.decode() 
    sock.close()

    if message == "ERR Syntax" or message == "ERR Not Found":
        sys.exit("Wrong syntax or server not found")

    ip = message.split(" ")
    return ip

def FSP(file_ip, path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((file_ip[0], int(file_ip[1])))
    message = "GET " + path + " FSP/1.0\r\nHostname: Test\r\nAgent: xnorek01\r\n\r\n"
    sock.send(message.encode())
   
    header = sock.recv(2048)
    test = re.match(r"FSP/1.0\sSuccess\r\nLength:[0-9]+\s*\r\n\r\n", header.decode())
    if not test:
        print("Invalid header recieved or file server returned error")

    get_length = header.decode().split(":")
    length = int(get_length[1])
    
    name = path.split("/")
    name = name[-1]
    f = open("%s" % name, "wb")
    while length > 0:
        test = sock.recv(4096)
        length -= 2048
        f.write(test)
    sock.close()

def main():
    host, port, server = argument_parser()
    test = server.split("/", 1)
    path = test[1]
    try: 
        message = NSP(host, port, test[0])
    except socket.timeout:
        sys.exit("Socket Timeout")
    file_ip = message[1].split(":")
    try:
        FSP(file_ip, path)
    except OSError:
        sys.exit("OSError")

if __name__ == "__main__":
    main()



