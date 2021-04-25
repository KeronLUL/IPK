## IPK project 2 - ZETA (packet sniffer)

Author: Karel Norek, xnorek01

Date: 24.04.2021

---

### Implementation

Program sniffs packets and prints information about packet and packet data. <br>
Header (information about packet) contains time when packet was sniffed in GMT time, source (IP or MAC adress) and port if protocol has it, destination with samethings as source and length of packet in bytes. <br>
Sniffer takes only ethernet interfaces. <br> <br>

Header's unique information about different packets: <br>
TCP, and UDP - IP address and port <br>
ICMP - IP address without port <br>
ARP - MAC addresses


### Arguments
*no argument* : Print all available interfaces <br>
-i interface or --interface interface : If parametr interface is set, sniff on given interface. If not print all available interfaces. <br>
-p port : Filters only packets with given port <br>
--tcp or t : Filters only TCP packets <br>
--udp or u : Filters only UDP packets <br>
--arp : Filters only ARP packets <br>
--icmp : Filters only ICMP packets <br>
-n num : Number of sniffed packets <br>

### Build
Project can be built by `make`

Other uses with Makefile: <br>
 `make clean` - removes executable ipk-sniffer <br>
 `make tar` - Tape archive for submitting

### Sample

`sudo ./ipk-sniffer -i eth0 --tcp -n 20`