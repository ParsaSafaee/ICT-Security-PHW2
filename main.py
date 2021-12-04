import nmap
import os
import time
import socket


def ping():
    ip_addr = input("Please enter your IP/Domain: ")
    c = input("Count of pings: ")
    os.system("ping -c " + c + " " + ip_addr)


def pnmap():
    ip_addr = input("Please enter your IP/Domain: ")
    print("\n*** Scanning the url... ***\n")
    os.system("nmap " + ip_addr)


def livehosts():
    ip_addr = input('Enter the network address: ')
    host = socket.gethostbyname(ip_addr)
    start = int(input("Enter the starting Number: "))
    end = int(input("Enter the last Number: "))
    start_time = time.time()
    scanner = nmap.PortScanner()
    print("\n*** Scanning... ***\n")
    for num in range(start, end + 1):
        ip = host[0:-1] + str(num)
        scanner.scan(ip, '1', '-v')
        if scanner[ip].state() == "up":
            print(ip, "--> Live")

    print("Scanning done after", time.time() - start_time, "s")


def openports():
    start_time = time.time()
    ip_addr = input('Enter the remote host IP to scan: ')
    host = socket.gethostbyname(ip_addr)
    begin = int(input("Enter the start port number: "))
    end = int(input("Enter the last port number: "))

    scanner = nmap.PortScanner()
    print("\n*** Searching for open ports... ***\n")
    print("Open ports: ")
    for num in range(begin, end + 1):

        res = scanner.scan(host, str(num))

        status = res['scan'][host]['tcp'][num]['state']
        if status == 'open':
            print(num, '--> ' + socket.getservbyport(num, 'tcp'))
    print("Scanning done after", time.time() - start_time, "s")


def findservices2():
    connected = False
    ip_addr = input('Enter the remote host IP to scan: ')
    host = socket.gethostbyname(ip_addr)
    port = int(input("Enter the start port number: "))  # First port.
    end = int(input("Enter the last port number: "))
    start_time = time.time()
    while port <= end:  # port 65535 is last port you can access.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)  # Create a socket.
        try:
            s.connect((host, port))
            connected = True
        except ConnectionRefusedError:
            connected = False
        finally:
            if connected and port != s.getsockname()[1]:  # If connected,
                try:
                    print("{}: Port {} Open --> {}".format('TCP', port, socket.getservbyport(port, 'tcp')))
                except socket.error:
                    pass
            port = port + 1  # Increase port.
            s.close()  # Close socket.
    print("Scanning done after", time.time() - start_time, "s")


def findservices1():
    open_ports = []
    ip_addr = input('Enter the remote host IP to scan: ')
    var = os.popen("nmap " + ip_addr).read()
    var = var.splitlines()
    for line in var:
        if len(line) < 1:
            continue
        if line.split()[0].split('/')[0].isdecimal():
            open_ports.append(line.split()[0].split('/')[0])
    for port in open_ports:
        var = os.popen("nmap -PN -p " + str(port) + " -sV " + ip_addr).read()
        var = var.splitlines()
        for line in var:
            if len(line) < 1:
                continue
            if line.split()[0].split('/')[0].isdecimal():
                protocol = line.split()[0].split('/')[1]
                status = line.split()[1]
                service = line.split()[2]
                version = " ".join(line.split()[3:]) if len(" ".join(line.split()[3:])) > 1 else "unknown"
                print("{}: Port {} {} --> Service: {}, Version: {}".format(protocol, port, status, service, version))
                break


if __name__ == '__main__':
    print('Hi, what do you want to do? Please enter your choice number:')
    while True:
        print(' 1: Ping a url \n 2: Use nmap on a url \n 3: Scan live hosts \n '
              '4: Check for open ports & services \n 5: Check for open ports & services (Socket approach)')
        c1 = int(input('\n >> '))
        if c1 == 1:
            ping()
        if c1 == 2:
            pnmap()
        if c1 == 3:
            livehosts()
        if c1 == 4:
            findservices1()
        if c1 == 5:
            findservices2()
        c2 = input("Anything else? [y/n] >> ")
        if c2 == 'y':
            continue
        else:
            break
