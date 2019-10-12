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

    # Length of ack-nak section
    ACK_NAK_length = 2
    
    ## initialize each packet with a sequence number and message    
    def __init__(self, seq_num: int, msg_S: str = "", ACK: int = 0, NAK: int = 0):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ACK = ACK
        self.NAK = NAK

    @classmethod
    def from_byte_S(self, byte_S: str):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length + Packet.seq_num_S_length])
        ack = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length: Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length + Packet.ACK_NAK_length - 1]
        nak = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length + Packet.ACK_NAK_length - 1: Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length + Packet.ACK_NAK_length]
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length + Packet.ACK_NAK_length:]
        return self(seq_num, msg_S, int(ack), int(nak))

        
    def get_byte_S(self) -> str:
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #print (seq_num_S)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + self.ACK_NAK_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        #print(length_S + seq_num_S + str(self.ACK) + str(self.NAK) + self.msg_S)
        checksum = hashlib.md5((length_S + seq_num_S + str(self.ACK) + str(self.NAK) + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string

        # print("Length: " + length_S)
        # print("Seq_num_S: " + seq_num_S)
        # print("checksum_S: " + checksum_S)
        # print("self.ACK: " + str(self.ACK))
        # print("self.isNAK: " + str(self.NAK))
        # print("self.msg_s: " + self.msg_S)
        #print( length_S + seq_num_S + checksum_S + self.msg_S)
        return length_S + seq_num_S + checksum_S + str(self.ACK) + str(self.NAK) + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S: str) -> bool:
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length : Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length]
        ack_nak_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length: Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length + Packet.ACK_NAK_length]
        msg_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length + Packet.ACK_NAK_length :]

        #print(length_S)
        #print(seq_num_S)
        #print(checksum_S)
        #print(ack_nak_S)
        #print(msg_S)
        #print(str(length_S + seq_num_S + ack_nak_S + msg_S))

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + ack_nak_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()

        #and check if the same
        return checksum_S != computed_checksum_S
    
    def isACK(self) -> bool:
        return self.ACK == 1

    def isNAK(self) -> bool:
        return self.NAK == 1

    def print_debug(self):
        print("Seq_num_S: " + str(self.seq_num))
        print("self.ACK: " + str(self.ACK))
        print("self.isACK(): " + str(self.isACK()))
        print("self.NAK: " + str(self.NAK))
        print("self.isNAK(): " + str(self.isNAK()))
        print("self.msg_s: " + self.msg_S)


# Should just put corruption checking in try catch block

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = '' 
    role_S = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
        self.role_S = role_S
    
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

            
    ###########
    #     SEND 
    ###########
    def rdt_2_1_send(self, msg_S):

        p = Packet(self.seq_num, msg_S)
        #self.seq_num += 1

        # Wait for ack or nak
        #print("Entering while")
        messageString = p.get_byte_S()
        self.network.udt_send(messageString)
        print("*** seq num " + str(p.seq_num) + " sent from " + self.role_S +": "+ msg_S+ " and waiting for ACK ***\n")

        while True:

            self.byte_buffer = ''

            while len(self.byte_buffer) == 0:
                #print("Reading response...")
                self.byte_buffer += self.network.udt_receive()

            length = int(self.byte_buffer[:Packet.length_S_length])

            try:
                responsePacket = Packet.from_byte_S(self.byte_buffer[0:length])
            except:
                print("Response packet corrupt, resend")
                self.network.udt_send(messageString)
                continue

            print("receiving byte buffer: " + self.byte_buffer)    
            if (len(responsePacket.msg_S) > 54):
                print("response packet not ACK/NAK, resending packet "  + str(p.seq_num))
                self.network.udt_send(p.get_byte_S())
                continue
                
            #print()
            #responsePacket.print_debug()
            #print(responsePacket.isACK())
            
            if responsePacket.isACK():
                #self.seq_num += 1
                print("packet " + str(p.seq_num) + " ACK'ed!")
                print("ACK " + self.byte_buffer[0:length])
                self.seq_num = (self.seq_num + 1)# % 2
                break

            if responsePacket.isNAK():
                print("packet " + str(p.seq_num) + " NAK'ed! resend packet")
                self.network.udt_send(p.get_byte_S())
                
                continue

    #############
    #    RECEIVE
    #############
    def rdt_2_1_receive(self):

        # print("rdtreceive21 called")
        ret_S = None
        self.byte_buffer=''
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
            #send NAK if corrupt
            print("\npacket received")
            try:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
            except Exception as e:
                # print(e)
                #reset buffer to exit while loop
                self.byte_buffer = ''
                #Send NACK
                NAK = Packet(self.seq_num, NAK=1)
                print("packet is corrupt:\n send NAK packet: " + NAK.get_byte_S())
                self.network.udt_send(NAK.get_byte_S())
                break
            print("packet number: " + str(p.seq_num))
            # not corrupt, expected sequence number
            if (p.seq_num == self.seq_num):
                print("packet matches expected seq number")
                #deliver data: 
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                #remove the packet bytes from the buffer
                self.byte_buffer = ''

                #send ACK
                ACK = Packet(self.seq_num, ACK=1)
                print("send ack packet: " + ACK.get_byte_S())
                self.network.udt_send(ACK.get_byte_S())
                #print("ack sent after receiving")

                #increment sequence
                self.seq_num = (self.seq_num + 1)# % 2
                

            # not corrupt but old sequence
            elif (p.seq_num != self.seq_num):
                print("wrong sequence received, send new ack")
                #reset buffer to exit while loop
                ret_S = None
                self.byte_buffer = ''
                #send ACK
                ACK = Packet(p.seq_num, ACK=1)
                #print("ack packet: " + ACK.get_byte_S())
                self.network.udt_send(ACK.get_byte_S())
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
        


        
        
