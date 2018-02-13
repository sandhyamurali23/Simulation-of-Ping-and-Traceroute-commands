
import socket, sys
import struct
import time
import select
import random

BIT_SHIFT=8 #bit shift
ICMP_ECHO_REQUEST=8 #icmp protocol 8

def main(input_val):
    '''
    Reads the command line arguements to perform necessary PING operations
    @param: input_val : list of command line arguements

    '''
    
    i=0 #index position of list
    count=float("inf") #count is set to infinity by default
    wait=1 #wait for 1 second default
    timeout=float("inf") #timeout is 2 seconds by default
    packet_size=56 #default packet size is 56
    
    dest_address=input_val[len(input_val)-1] #dest address
    
    while(i<len(input_val)):

        if(input_val[i]=='-t'): #check if timeout is present
            timeout=int(input_val[i+1])
            
        elif(input_val[i]=='-c'): #check if count is present
            count=int(input_val[i+1])
            
        elif(input_val[i]=='-i'): #check if wait is present
            
            wait=int(input_val[i+1])
        
        elif(input_val[i]=='-s'): #check if packet size is present
            
            packet_size=int(input_val[i+1])
        
        i+=2
            
        
        
            
    ping_destination(dest_address,timeout,count,wait,packet_size) #pings the destination
    
    
def create_raw_socket(dest_address):
    
    '''
    Creates raw socket using icmp header
    @param: dest_address : destination address
    @return: socket_raw: raw socket

    '''
    
    icmp=socket.getprotobyname("icmp") #gets icmp icmp protocol
    
    try:
        socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) #creates raw socket
    except socket.error:
        msg='ICMP failure'
        print ('Socket could not be created. Error Code : ' + msg)
        sys.exit()
        
    return socket_raw

def compute_checksum(data):
    
    '''
    Computes checksum
    @param: data : header+data value
    @return checksum value

    '''
    
    total=0 #total result
    index=0 #iterator
    
    while(index<len(data)):
        word=0
        word=data[index]+(data[index+1]<<8) #consider 16 bit word
        
        carry=total+word #determine carry
        total=(carry & 0xffff)+(carry>>16) #add carry to result
        index+=2
        
    return ~total & 0xffff
       
def send_ping(dest_address,socket_raw,packet_id,packet_size):
    
    '''
    Sends ping to destination
    @param: dest_address : destination address
    @param: socket_raw: raw socket
    @param: packet_id: packet id
    @param: packet_size: packet size
    @return 1: if packet sent successfully, 0 otherwise

    '''
    if(packet_size%2==1):
        packet_size=packet_size+1
        
    header=struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, packet_id, 1) #pack the icmp header
    data=b'1'*packet_size #create data in bytes
    packet=header+data
    
    checksum=compute_checksum(header+data) #compute checksum
    checksum_htons=socket.htons(checksum) #convert checksum to host to network 
    header=struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum_htons), packet_id, 1) #pack the resultant checksum
    
    total_data=header+data
    
    try:
        
        socket_raw.setsockopt(socket.SOL_IP,socket.IP_TTL,255) #create IP header with ttl 255
        socket_raw.sendto(total_data,(socket.gethostbyname(dest_address),1)) #send packet to destination
        return 1
    except:
        return 0
        
    

def receive_ping(socket_raw,packet_id,time_sent_packet,timeout_threshold):
    
    '''
    Receive ping from source
    @param: socket_raw: raw socket
    @param: packet_id: packet id
    @param: time_sent: time the packet was sent
    @param: timeout_threshold: timeout value
    @return: list_contents: list of values needed to display in ping

    '''
    
    
    while True:
        
        ready_state=select.select([socket_raw],[],[],timeout_threshold) #determine the data from the socket
        
        
        
        if(ready_state[0]==[]): #if no data
            return 
        
        time_receive_packet=time.time() #time packet is received
        packet,address=socket_raw.recvfrom(1024) #receive 1024 byte data
        
        
        icmp_header=packet[20:28] #get icmp header
        
        
        ip_header=packet[0:20] #get ip header
        
        ip_header_data = struct.unpack('!BBHHHBBH4s4s', ip_header) #unpack ip header
        ttl=ip_header_data[5] #get ttl value packed
                
    
        type,code,checksum,packetID,sequence=struct.unpack("bbHHh", icmp_header) #unpack icmp header
        
        if(packetID==packetID): #check packet ID
            round_trip_time=time_receive_packet-time_sent_packet #compute round trip time and append contents
            list_contents=[]
            list_contents.append(round_trip_time)
            list_contents.append(ttl)
            list_contents.append(address)
            return list_contents
        
        
    
def ping_destination(dest_address,timeout,count,wait,packet_size):
    
    '''
    Receive ping destination by creating raw sockets
    @param: dest_address: destination address
    @param: timeout: timeout value
    @param: count: number of ping requests
    @param: wait: time to wait between sending packets
    @param: packet_size: size of packet

    '''
    
    
    seq_no=0 #sequence number of packets
    iterations=0 #iterations
    c=0 #counter to increment if count is specified and finite
    packet_loss=0 #check for packet loss
    packet_transmitted=0 #number of packets transmitted
    
    time_left=0 #time left in case of timeout
    
    if(timeout!=float("inf")):
        time_left=0
    else:
        time_left=float("inf")
    
    if count==float("inf"): #check if count is finite and specified
        count=True
        c=0
    elif count<=0: #check if count specified is negative
        print('ping: invalid count of packets to transmit:',count)
        sys.exit()
    try:        
        while count:

            socket_raw=create_raw_socket(dest_address) #create raw sockets
            packet_id=int((id(random.random()) % 65535)) #create packet id

            flag_send=send_ping(dest_address,socket_raw,packet_id,packet_size) #send ping
            packet_transmitted+=1 


            if(flag_send==0 and iterations>0): #if fail to send and not the first request
                print('ping: sendto: No route to host')
                print('Request timeout for icmp_seq ',seq_no)
                seq_no+=1
                iterations+=1
                packet_loss+=1

            elif(flag_send==0 and iterations==0): #if fail to send and first iteration
                print('ping: cannot resolve ', dest_address,' : Unknown host')
                sys.exit()

            elif(flag_send==1): #if packet sent

                if(iterations==0): #if first iteration
                    print('PING ',dest_address,'(',socket.gethostbyname(dest_address),')'," : ",packet_size," data bytes")

                if(packet_size<0):
                    print('ping: sendto: Invalid argument')
                    print('Request timeout for icmp_seq ',seq_no)
                    packet_loss+=1



                response=receive_ping(socket_raw,packet_id,time.time(),2) #receive ping

                if(response==None): #if no data present
                    print('Request timeout for icmp_seq ',seq_no) #indicates timeout and packet loss
                    packet_loss+=1

                else:
                    #take contents from the list and print the content
                    round_trip_time=response[0]
                    ttl=response[1]
                    address=response[2]
                    round_trip_time_milliseconds=round_trip_time*1000 
                    total_data=packet_size+8

                    if(packet_size>=0):
                        print(total_data,' bytes from ',address[0],'icmp_seq = ',seq_no,' ttl = ',ttl,' time =',     round(round_trip_time_milliseconds,3),' ms') 
                seq_no=seq_no+1
                iterations+=1

            time.sleep(wait) #wait between two packets
            if(count!=True): #if count is finite and specified
                c+=1 #increment count
                if(c>=count):
                    break
            if(time_left!=float("inf")):
                time_left=time_left+wait #compute time to check timeout


                if(time_left==timeout): #check timeout
                    break
    except KeyboardInterrupt:
        pass

    
        
    print('--- ',dest_address,' ping statistics ---')
            
        
    transmitted=packet_transmitted #transmitted packets
    packet_received=transmitted-packet_loss # packets received
    loss_percent=(packet_loss/transmitted)*100 #loss percent
    print(transmitted,' packets transmitted,', packet_received,' packets received, ',loss_percent,'% packet loss')
        
                
            
        
            
if __name__ == '__main__':
    main(sys.argv[1:])
        
        