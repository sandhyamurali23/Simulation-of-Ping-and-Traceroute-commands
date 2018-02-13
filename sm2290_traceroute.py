import socket
import time
import select
import sys
import random
import struct

BIT_SHIFT=8 #bit shifting by 8
ICMP_ECHO_REQUEST=8 #ICMP request 8


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


def check_address_reachable(dest_address):
    
    '''
    Creates check if destination is reachable
    @param: dest_address: destination address
    @return: dest_addr:IP address of the host

    '''
    
    try:
        dest_addr=socket.gethostbyname(dest_address) #get host name
    except:
        print('traceroute: unknown host',dest_address)
        sys.exit()
    
    return dest_addr


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

def send_message(dest_address,socket_raw,packet_id,ttl):
    
    '''
    
    Creates packet to send the packet
    @param: dest_address: destination address
    @param: socket_raw: raw socket
    @param: packet_id: packet id
    @param: ttl: ttl 
    @return socket_raw: raw socket
    @return total_data: total_data 
     
    '''
    
    header=struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, packet_id, 1) #pack the header
    data=b'1'*52 #create data
    packet=header+data 
    checksum=compute_checksum(header+data) #computes checksum
    checksum_htons=socket.htons(checksum) #convert to host to network
    header=struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum_htons), packet_id, 1) #pack the checksum
    
    total_data=header+data
    socket_raw.setsockopt(socket.SOL_IP,socket.IP_TTL,ttl)
    
    return socket_raw,total_data
        

def traceroute(dest_address,minus_n_present,n_queries,S_present):
    
    '''
    
    Performs traceroute
    @param: dest_address: destination address
    @param: minus_n_present: -n present to display IP address
    @param: n_queries: number of probes
    @param: S_present: -S present to display loss percent
     
    '''
    
        
    #port = 33434
    max_hops = 64 #max hops
    ttl = 1 #ttl iteration
    dest_addr=check_address_reachable(dest_address) #determine IP address if reachable
    flag=0 #flag to check if we got response from the hop router
    
    print('traceroute to ',dest_address,'(',dest_addr,'), ',max_hops,' hops max,', '52 byte packets')
    try:
        while True:

            socket_raw=create_raw_socket(dest_address) #create socket
            packet_id=int((id(random.random()) % 65535)) #create packet id
            socket_raw,data=send_message(dest_address,socket_raw,packet_id,ttl) #sends message to destination

            string=""
            flag=0
            flag_fail=0 #determine if fail to reach
            count=0 #iterations count
            count_probes_not_answered=0 # number probes not answered
            c_fail=0 #count fail responses received

            #print(minus_n_present,n_queries,S_present)
            for i in range(n_queries):


                try:
                    socket_raw.sendto(data, (dest_address,1)) #send to destination
                    time_sent=time.time() #set send time
                except:
                    if(count==0): #if first iteration and fail to reach
                        flag_fail=1 
                        c_fail+=1
                        count+=1

                        if(count==n_queries): #if count reaches maximum ttl hops
                            loss_percent=(c_fail/n_queries)*100 #loss percent
                            print('* traceroute: sendto: Cant assign requested address')
                            print('traceroute: wrote ',dest_address,' 52 chars, ret=-1','(',loss_percent,'% loss)')

                        else:
                            print('* traceroute: sendto: Cant assign requested address')
                            print(ttl,'traceroute: wrote ',dest_address,' 52 chars, ret=-1')


                    else: #if not first iteration and fail to reach

                        c_fail+=1
                        count+=1

                        if(count==n_queries): #if count reaches maximum ttl hops
                            loss_percent=(c_fail/n_queries)*100
                            print('* traceroute: sendto: Cant assign requested address')
                            print('traceroute: wrote ',dest_address,' 52 chars, ret=-1','(',loss_percent,'% loss)')

                        else:
                            print('* traceroute: sendto: Cant assign requested address')
                            print('traceroute: wrote ',dest_address,' 52 chars, ret=-1')






                ready_state=select.select([socket_raw],[],[],2) #determine the data from the socket

                if(ready_state[0]==[]): #if no data received
                    curr_host=""
                    string+="*"+"   "
                    count_probes_not_answered+=1 #increment probes not answered
                    continue

                else:
                    flag=1 #if data received



                packet, curr_addr = socket_raw.recvfrom(512) #receive 512 bytes of data
                time_receive=time.time() #receive time
                curr_addr = curr_addr[0] #IP address


                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0] #get host name
                except socket.error:
                    curr_name = curr_addr

                if(flag==1):
                    addr=curr_addr
                    host="%s (%s)" % (curr_name, curr_addr) 
                else:
                    curr_host = "%s (%s)" % (curr_name, curr_addr)

                round_trip_time=time_receive-time_sent #calculate round trip time
                round_trip_time_milliseconds=round(round_trip_time*1000,2) #round ms to 2 decimals
                string+=str(round_trip_time_milliseconds)+"ms"+"     "

            if(count_probes_not_answered==n_queries and c_fail!=n_queries): #if not total failure in iteration
                if(S_present==True): #if -S present
                    loss_percent=(count_probes_not_answered/n_queries)*100
                    print(ttl,"    ",string,'(',loss_percent,'% loss)')
                else:
                    print(ttl,"    ",string)



            elif(c_fail<n_queries): #if only some failure of rtt has happened
                if(minus_n_present==False): #-n present
                    if(S_present==True): #-S present
                        loss_percent=(count_probes_not_answered/n_queries)*100
                        print(ttl,"    ",host,"    ",string,'(',round(loss_percent,2),'% loss)')
                    else:
                        print(ttl,"    ",host,"    ",string)
                elif(minus_n_present==True): 
                    if(S_present==True):
                        loss_percent=(count_probes_not_answered/n_queries)*100
                        print(ttl,"    ",addr,"    ",string,'(',round(loss_percent,2),'% loss)')
                    else:
                        print(ttl,"    ",addr,"    ",string)





            ttl += 1 #ttl value incremented
            if curr_addr == dest_addr or ttl>max_hops: #check if destination is reached or ttl limit reached
                break
    except KeyboardInterrupt:
            pass
            
            
            
def main(input_val):
    '''
    Reads the command line arguements to perform necessary Traceroute operations
    @param: input_val : list of command line arguements

    '''
    
    i=0 #index position of list
    minus_n_present=False #check if -n present
    n_queries=3 #n_queries ttl limit
    S_present=False #-S present
    dest_addr=input_val[len(input_val)-1] #dest address
    
    while(i<len(input_val)):

        if(input_val[i]=='-n'): #if -n present 
            minus_n_present=True
            
        elif(input_val[i]=='-q'): #if -q present 
            n_queries=int(input_val[i+1])
            
        elif(input_val[i]=='-S'): #if -S present
            S_present=True
        
        i+=1
    

    traceroute(dest_addr,minus_n_present,n_queries,S_present) #traceroute 
    
    
        
        
if __name__ == "__main__":
    
    main(sys.argv[1:])
        
        