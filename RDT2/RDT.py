import Network 
import argparse
from time import sleep
import hashlib

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32 
    
    ## initialize each packet with a sequence number and message    
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)

        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        print (seq_num_S)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        # print("Length: " + length_S)
        # print("Seq_num_S: " + seq_num_S)
        # print("checksum_S: " + checksum_S)
        # print("self.msg_s: " + self.msg_S)
        #print( length_S + seq_num_S + checksum_S + self.msg_S)
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = '' 

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes

            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length

            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet

            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
#            if (Packet.corrupt(byte_S)):
#                ret_S = "corrupt"
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration

            
    #############
    # TODO:
    # 1. reciever sends back packet with "ACK" "NAK"
    # 2. 
    #############
    def rdt_2_1_send(self, msg_S):

        p = Packet(self.seq_num, msg_S)
        print("***" + msg_S + " sent and waiting for ACK ***")

        # Wait for ack or nak
        while True:

            self.network.udt_send(p.get_byte_S())
            #print("i'm looping here")

            # Get recienver response....
            # How do we do this?

            while True: 
                response = self.rdt_1_0_receive()
                if (not response == None):
                    #print(str(response) + "!!!")
                    break

            if (response == "corrupt" or "NAK"):
                continue

            # Check if ACK, then return
            elif (response == "ACK"):
                print("ACK RECEIVED")

                #Increment sequence when ACK received
                self.seq_num = (self.seq_num + 1) % 2
                break


    #############
    # TODO:
    # 1. reciever sends back packet with "ACK" "NAK"
    # 2. 
    #############
    def rdt_2_1_receive(self):

        # print("rdtreceive21 called")
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S

        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])

            if (Packet.corrupt(byte_S)):
                #reset buffer to exit while loop
                self.byte_buffer = self.byte_buffer[length:]
                #Send NACK
                nack = Packet(self.seq_num, "NAK")
                self.network.udt_send(nack.get_byte_S())

            # not corrupt, expected sequence number
            elif (p.seq_num == self.seq_num):
                
                #deliver data: 
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                #remove the packet bytes from the buffer
                self.byte_buffer = self.byte_buffer[length:]

                #send ACK
                ack = Packet(self.seq_num, "ACK")
                print("ack packet: " + ack.get_byte_S())
                self.network.udt_send(ack.get_byte_S())
                print("ack sent after receiving")

                #increment sequence
                self.seq_num = (self.seq_num + 1) % 2
                

            # not corrupt but old sequence
            elif (p.seq_num != self.seq_num):
                #reset buffer to exit while loop
                ret_S = None
                self.byte_buffer = self.byte_buffer[length:]
                #send ACK
                ack = Packet(self.seq_num, "ACK")
                self.network.udt_send(ack.get_byte_S())
                print("old sequence number, ack sent")
            
        
    
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        
