"""As always run this tool at your own risk etc. You will need to check that negotiations using 3DES,MD5/SHA1,DH2 are enabled as support for other transforms has not been added. If you receive 0 packets this will probably because transforms negotiation failed"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys,os,time,threading,SocketServer,socket,thread
from scapy.all import *
from optparse import OptionParser

usageString = "Usage: %prog -w /path-to/wordlist.txt -t target"
parser = OptionParser(usage=usageString)
parser.add_option("-w","--wordlist",dest="file",default=None,type="string",help="Path to wordlist file")
parser.add_option("-t","--target",dest="trgt",default=None,type="string",help="Target IP address")
parser.add_option("-s","--hash",dest="hash",default="SHA",type="string",help="Hash type for transform. Specify either SHA or MD5 specifically, default is SHA")


(opts,args) = parser.parse_args()
trgt = opts.trgt
file = opts.file
hash = opts.hash

#check required arguments are provided
if opts.trgt == None or opts.file == None:
 parser.error("Hostname required")

#Build the packet
cky_i='\xf1\xd5\xb0Y\xc5\xb1z\xcf'
transforms=[('Encryption', '3DES-CBC'), ('Hash', hash), ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L,)]
trans=ISAKMP_payload_Transform(next_payload=3, res=0, num=1, id=1, res2=0, transforms=transforms)
prop = ISAKMP_payload_Proposal(next_payload=None, res=0, proposal=1, proto=1, SPIsize=0, trans_nb=1, SPI='', trans=trans)
ke='\x06C\x92\xcb\x1f\xa5\xc9\xd4\\w\x11\x08\xbf\xe4d\xbd\x88b\x07.=\x07\x8e^Yzh\x13N\x9a\xcb\x1f^\x07\xd8\xc9\x0f\x99\x8es\xe0\x12\xa3\x89\xa8\xa2\xd4\x9c`\xbe\xeeU\x99D\xea\xda\x11\\a\xd3a\xca\x86\x0bSh/\xf0\xa7\xde\xe9\xc2\xd9\x94O5~5\xa6\xdd\x84\xc1\x91L\x9f\x84\xc2_\xed\xabR;d\x05\x88 iV\xd7\x19\xdfo\xcc\xf6\x97\xc6t\xe9\xb8\x89c\x07\x01\x9c;\x97\x1e\xe5\x86\xe7\x07\xe5\xbc\x90\xfd\xac:\r'
nonce='\x92%\xd3\x89\xc6\x07m\x1b^\xd9\x97\x95\xa7\xa1\xb9`\x98UMw'


#Thread to send the IKE packet
def ike(group):
    threading.Thread(target=send(group)) 
 

#Socket server handler
class Cap(SocketServer.BaseRequestHandler):
    def server_bind(self):
       print server.server_address
       self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,SO_REUSEPORT, 1)
       self.socket.bind(self.server_address)
       self.socket.setblocking(0)

    def handle(self):
        request, socket = self.request
        data = request
        packets.append(data)

#Thread for the socket server with timeout 
def serve_thread_udp(host, port, handler):
    server = SocketServer.UDPServer((host, port), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start() 
    time.sleep(30)
    server.shutdown()


#Main function looping through supplied wordlist and applying each word as a group ID. If more than 1 response packet (currently set to 2 for false positive reduction) is received before the timeout period expires the group ID is correct.
def main():
 print "Please be patient each guess will need to wait for all responses"
 f = open(opts.file,"r")
 word = f.readlines()
 f.close()
 for w in word:
  Group = w.strip()
  print "Trying group - %s..."%Group
  pkt = IP(dst=trgt)/UDP()/ISAKMP(init_cookie=cky_i,next_payload=1,exch_type=4)/ISAKMP_payload_SA(next_payload=4,DOI=1,prop=prop)/ISAKMP_payload_KE(next_payload=10,load=ke)/ISAKMP_payload_Nonce(next_payload=5,load=nonce)/ISAKMP_payload_ID(IDtype=3,ProtoID=17,Port=500,load=Group)
  ike(pkt)
  serve_thread_udp('', 500, Cap)
  pCount = len(packets)
  print "Packets received = ",pCount
  if pCount > 2:
   print "Correct group name found: ",Group
   exit()
  if w == None:
   print "Group name not found - try another wordlist"
   exit()
  else:
   print "Incorrect group name\n\n"
  packets[:] = []   

packets = []
main()
