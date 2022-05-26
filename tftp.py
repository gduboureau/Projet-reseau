"""
TFTP Module.
"""
import threading
import socket
import sys

########################################################################
#                          COMMON ROUTINES                             #
########################################################################

def get_file(sock,filename):
    cpt = 1
    # wait for file content and decode it
    while True:
        data, address = sock.recvfrom(1500)
        if data == b'':
            break
        frame = data
        frame1 = frame[4:]
        file = open(filename,"ab")
        file.write(frame1)
        file.close()
        # send ACK1 
        addr , port  =  sock.getsockname()
        print("["+str(address[0])+":"+str(address[1])+" -> "+str(addr)+":"+str(port)+"] DAT"+str(cpt)+"="+str(data))
        sock.sendto(b'\x00\x04'+(cpt).to_bytes(2, byteorder='big'),address)
        cpt += 1

def put_file(filename,sock,addr,blksize):
    file = open(filename, 'rb')
    cpt = 1
    while True:
        char = file.read(blksize)
        if not char:
            sock.sendto(b'',addr)
            break
        a = b'\x00\x03'+(cpt).to_bytes(2, byteorder='big')+char
        # send file content
        sock.sendto(a,addr)
        # wait ACK1 
        data, adress = sock.recvfrom(1500)
        addr1 , port  =  sock.getsockname()
        print("["+str(addr[0])+":"+str(addr[1])+" -> "+str(addr1)+":"+str(port)+"] ACK"+str(cpt)+"="+str(data))
        cpt += 1
    file.close()
    sock.close()
    
########################################################################
#                             SERVER SIDE                              #
########################################################################


def runServer(addr, timeout, thread):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr))
    print("Server started with option <thread> =",thread)
    print("Waiting for clients requests :")
    while True :
        data, address = s.recvfrom(1500)
        print("Client connected :",address,", Start transfer of file ==>\n")
        frame = data                                      # sample of WRQ as byte array ex: b'\x00\x02test.txt\x00octet\x00'  
        frame1 = frame[0:2]                               # frame1 = b'\x00\x02'
        frame2 = frame[2:]                                # frame2 = b'test.txt\x00octet\x00'
        opcode = int.from_bytes(frame1, byteorder='big')  # opcode = 2
        args = frame2.split(b'\x00')                      # args = [b'test.txt', b'octet', b'']
        if len(args) == 5:
            blksize = args[3].decode('ascii')
        else:
            blksize = 512
        filename = args[0].decode('ascii')                # filename = 'test.txt'
        mode = args[1].decode('ascii')                    # mode = 'octet'
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # put
        if opcode == 2:  
            # send ACK0 to client  
            try:
                print("["+str(address[0])+":"+str(address[1])+" -> "+str(addr[0])+":"+str(addr[1])+"] WRQ="+str(data))
                new_sock.sendto(b'\x00\x04\x00\x00',address)
            # get file from client
                if thread == False:
                    get_file(new_sock,filename)
                else:    
                    t = threading.Thread(None, get_file, None, (new_sock,filename, ))
                    t.start()
            except Exception as e:
                print("ERROR : ",e)
        # get
        if opcode == 1:
            print("["+str(address[0])+":"+str(address[1])+" -> "+str(addr[0])+":"+str(addr[1])+"] RRQ="+str(data))
            # send file to client
            try:
                if thread == False:
                    put_file(filename,new_sock,address,int(blksize))
                else:
                    t = threading.Thread(None, put_file, None, (filename,new_sock,address,int(blksize), ))
                    t.start()
            except Exception as e:
                print("ERROR : ",e)
            

########################################################################
#                             CLIENT SIDE                              #
########################################################################

def put(addr, filename, targetname, blksize, timeout):
    try:
        open(filename,"rb")
    except Exception as e:
        print("ERROR :",e)
        sys.exit(1)
    if targetname == '':
        if blksize == 512:
            file = '\x00\x02'+filename+'\x00octet\x00'
        else:
            file = '\x00\x02'+filename+'\x00octet\x00blksize\x00'+str(blksize)+'\x00'
    else:
        if blksize == 512:
            file = '\x00\x02'+targetname+'\x00octet\x00'
        else:
            file = '\x00\x02'+targetname+'\x00octet\x00blksize\x00'+str(blksize)+'\x00'
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    # send file 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(file.encode(), addr)
    # wait ACK0 from server
    data, address_server = s.recvfrom(1500)
    addr_client , port_client  =  s.getsockname()
    print("["+str(address_server[0])+":"+str(address_server[1])+" -> "+str(addr_client)+":"+str(port_client)+"] ACK0="+str(data))
    s.settimeout(timeout)
    put_file(filename,s,address_server,blksize)

    
########################################################################


def get(addr, filename, targetname, blksize, timeout):
    if blksize == 512:
        file = '\x00\x01'+filename+'\x00octet\x00'
    else:
        file = '\x00\x01'+filename+'\x00octet\x00blksize\x00'+str(blksize)+'\x00'
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # send file
    try :
        s.sendto(file.encode(), addr)
        s.settimeout(timeout)
        if targetname == '':
            get_file(s,filename)
        else:
            get_file(s,targetname)
    except:
        sys.exit(1)

# EOF

