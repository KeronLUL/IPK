#!/usr/bin/env python3
import socket
import argparse
import re
import sys
import os

# Argument parser
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

    port = re.match(r"^[\d]+$", ip[1])
    if not port:
        sys.exit("Invalid port")

    return ip[0], int(ip[1]), foo[1]

# Function that gets ip of file server from name server using UDP connection
def NSP(host, port, server):
    message = "WHEREIS " + server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(30)
    sock.connect((host, port))
    sock.send(message.encode())
    data = sock.recv(1024)
    message = data.decode() 
    sock.close()

    if message == "ERR Syntax" or message == "ERR Not Found":
        sys.exit("Wrong syntax or server not found")
    ip = message.split(" ")
    return ip

# Function that gets data from file server using TCP connection
def FSP(file_server_ip, path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((file_server_ip[0], int(file_server_ip[1])))
    message = "GET " + path + " FSP/1.0\r\nHostname: Test\r\nAgent: xnorek01\r\n\r\n"
    sock.send(message.encode())

    header = sock.recv(4096)
    test = re.match(b"FSP/1.0\sSuccess\r\nLength:\s*[0-9]+\s*\r\n\r\n", header)
    if not test:
        if re.match(b"FSP/1.0\sNot Found", header):
            sys.exit("File not found")
        elif re.match(b"FSP/1.0\Bad Request", header):
            sys.exit("Bad request for file server")
        elif re.match(b"FSP/1.0\Server Error", header):
            sys.exit("Server Error")
        else: sys.exit("Invalid header")

    get_length = header.split(b":")
    line = get_length[1].split(b"\r", 1)
    write = line[1].split(b"\n\r\n")
    length = int(line[0])
    name = path.split("/")
    name = name[-1]
    try:
        f = open("%s" % name, "wb")
    except OSError:
        sys.exit("Coudln't open file")
    f.write(write[1])

    while length > 0:
        test = sock.recv(2048)
        length -= 2048
        f.write(test)
    f.close()
    if os.path.getsize(name) != int(line[0]):
        sys.exit("File size doesn't match")
    sock.close()

def FSP_check(file_server_ip, path):
    try:
        FSP(file_server_ip, path)
    except OSError:
        sys.exit("Couldn't connect to server")
    except ValueError:
        sys.exit("Invalid file server port")

def main():
    host, port, server_path = argument_parser()
    server = server_path.split("/", 1)
    try: 
        message = NSP(host, port, server[0])
    except socket.timeout:
        sys.exit("Socket Timeout")
    except socket.gaierror:
        sys.exit("Invalid IP")
    except OverflowError:
        sys.exit("Invalid port")
    file_server_ip = message[1].split(":")
    
    if server[1] == "*":
        path = "index"
        FSP_check(file_server_ip, path)
        try:
            f = open("index", "r")
        except OSError:
            sys.exit("Coudln't open file")
        lines = f.read().splitlines()
        for line in lines:
            path = line
            FSP_check(file_server_ip, path)
        f.close()
    else:
        path = server[1]
        FSP_check(file_server_ip, path)
    
if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(1)
