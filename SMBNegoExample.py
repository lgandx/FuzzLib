import sys, struct, socket, os
from socket import *
from lib import *
from time import sleep
from odict import OrderedDict

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))

def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

class SMBHeader(Packet):
    fields = OrderedDict([
        ("Proto", "\xff\x53\x4d\x42"),
        ("Cmd", "\x72"),
        ("Error-Code", "\x00\x00\x00\x00" ),
        ("Flag1", "\x18"),
        ("Flag2", "\x53\xc8"),
        ("PidHigh", "\x00\x00"),
        ("Signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Reserved", "\x00\x00"),
        ("Tid", "\xff\xff"),
        ("Pid", "\xff\xfe"),
        ("Uid", "\x00\x00"),
        ("Mid", "\x00\x00"),
    ])

class SMBNego(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x00"),
        ("Bcc", "\x62\x00"),
        ("Data", "")
    ])
    
    def calculate(self):
        self.fields["Bcc"] = struct.pack("<H",len(str(self.fields["Data"])))

class SMBNegoData(Packet):
    fields = OrderedDict([
        ("Separator","\x02" ),
        ("Dialect", "PC NETWORK PROGRAM 1.0\x00"),
        ("Separator1","\x02"),
        ("Dialect1", "LANMAN1.0\x00"),
        ("Separator2","\x02"),
        ("Dialect2", "Windows for Workgroups 3.1a\x00"),
        ("Separator3","\x02"),
        ("Dialect3", "LM1.2X002\x00"),
        ("Separator4","\x02"),
        ("Dialect4", "LANMAN2.1\x00"),
        ("Separator5","\x02"),
        ("Dialect5", "NT LM 0.12\x00"),
        ("Separator6","\x02"),
        ("Dialect6", "SMB 2.002\x00"),
        ("Separator7","\x02"),
        ("Dialect7", "SMB 2.???\x00"),
        ("Data", ""),
    ])


class SMBv2Header(Packet):
    fields = OrderedDict([
        ("PreServer", "\xfe"), 
        ("Server", "\x53\x4d\x42"),
        ("HeadLen", "\x40\x00"), 
        ("CreditCharge", "\x00\x00"),
        ("NTStatus","\x00\x00\x00\x00"),
        ("SMBv2Command","\x00\x00"),
        ("CreditRequested","\x00\x00"),
        ("Flags","\x00\x00\x00\x00"),
        ("ChainOffset","\x00\x00\x00\x00"),
        ("CommandSequence","\x01\x00\x00\x00\x00\x00\x00\x00"),
        ("ProcessID","\xff\xfe\x00\x00"),
        ("TreeID","\x00\x00\x00\x00"),
        ("SessionID","\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Signature","\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Data", ""),
        ])

    def calculateFuzz(self, n =1):

       fuzz = fuzzer()
       function=[
	{"HeadLen":        		fuzz.DispatchPackets(self.fields["HeadLen"])}, 
     ]
       for i in range(n):
           result = choice(function)
           self.fields.update(result)
           print "CalculateFuzz updated this len in SMBv2Header:",result #Here we print what we actually altered, pretty useful when you get a crash.

    def PreFuzz(self, n =1):
        fuzz = fuzzer()
        function=[
	{"PreServer":     	  		fuzz.DispatchPackets(self.fields["PreServer"])},
	{"Server":        		fuzz.DispatchPackets(self.fields["Server"])}, 
	{"SMBv2Command":     	 	fuzz.DispatchPackets(self.fields["SMBv2Command"])},
	{"CreditRequested":            	 	fuzz.DispatchPackets(self.fields["CreditRequested"])},
	{"Flags":       	 	fuzz.DispatchPackets(self.fields["Flags"])},
	{"ChainOffset":    	 	fuzz.DispatchPackets(self.fields["ChainOffset"])},
	{"CommandSequence":           	 	fuzz.DispatchPackets(self.fields["CommandSequence"])},
	{"ProcessID":        	 	fuzz.DispatchPackets(self.fields["ProcessID"])},
	{"TreeID":            	 	fuzz.DispatchPackets(self.fields["TreeID"])},
	{"SessionID":            	 	fuzz.DispatchPackets(self.fields["SessionID"])},
	{"Data":			fuzz.DispatchPackets(self.fields["Data"])},
     	]
	for i in range(n):
		result = choice(function)
		self.fields.update(result)
		print "Pre Fuzz updated this field in SMB2 Header:",result

# This class is basically the packet you're about to fuzz. Use Message Analyzer (MSFT), or Network Monitor (MSFT) for accurate SMB packet parsing (not like wireshark SMB parser).
# When you call SMB2Nego, you can edit any field by doing: SMB2Nego(Context3NetName="10.0.0.1"), lengths will be adjusted automatically when you call calculate(). 
class SMB2Nego(Packet):
    fields = OrderedDict([
        ("Len",               "\x24\x00"),
        ("DialectCount",      "\x05\x00"),
        ("SecurityMode",      "\x01"),
        ("NullTerminator",    "\x00\x00\x00"),
        ("Capabilities",      "\x7f\x00\x00\x00"),
        ("ClientGUID",        os.urandom(16)),
        ("NegoContextOffset", "\x70\x00\x00\x00"),
        ("NegoContextCount",  "\x04\x00"),
        ("Reserved",          "\x00\x00"),
        ("Dialects",          "\x02\x02\x10\x02\x00\x03\x02\x03\x11\x03"),
        ("Separator",          "\x00\x00"),
        ("Context1Type",             "\x01\x00"),
        ("Context1Len",              "\x26\x00"),
        ("Context1Reserved",         "\x00\x00\x00\x00"),
        ("Context1HashAlgoCount",    "\x01\x00"),
        ("Context1SaltLen",          "\x20\x00"),
        ("Context1HashAlgoType",     "\x01\x00"),
        ("Context1Salt",             "\x9d\x17\xd8\x0d\x2f\x57\xf1\xcd\x25\xbe\xb0\xac\x09\x6f\xab\x44\xa3\x79\x04\x88\x51\x22\xc4\xc1\xef\xc4\x65\xae\xd7\xe1\x6f\x98"),
        ("Separator2",               "\x00\x00"),
        ("Context2Type",             "\x02\x00"),
        ("Context2Len",              "\x06\x00"),
        ("Context2Reserved",         "\x00\x00\x00\x00"),
        ("Context2CipherCount",      "\x02\x00"),
        ("Context2Cipher1",          "\x02\x00"),
        ("Context2Cipher2",          "\x01\x00"),
        ("Separator4",               "\x00\x00"),
        ("Context4Type",             "\x03\x00"),
        ("Context4Len",              "\x0e\x00"),
        ("Context4Reserved",         "\x00\x00\x00\x00"),
        ("Context4Data",             "\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00"),
        ("Separator3",               "\x00\x00"), 
        ("Context3Type",             "\x05\x00"),
        ("Context3Len",              "\x1a\x00"),
        ("Context3Reserved",         "\x00\x00\x00\x00"),
        ("Context3NetName",          "192.168.0.176"),#your IP.
        ("Data",             ""), # We can add this field at the end of the packet so we're able to add some fuzzed data at the end of the packet and have all the lenghts correct.

    ])
    
    def calculate(self):
        self.fields["NegoContextOffset"] = struct.pack("<L",len(self.fields["NegoContextCount"]+self.fields["Reserved"]+self.fields["Dialects"]+self.fields["Separator"])+96)# Context offset.
        self.fields["Context3NetName"] =  self.fields["Context3NetName"].encode('utf-16le')
        self.fields["Context3Len"] = struct.pack("<H",len(str(self.fields["Context3NetName"])))
        self.fields["Context4Len"] = struct.pack("<H",len(str(self.fields["Context4Data"])))
	####
        self.fields["Context1SaltLen"] = struct.pack("<H",len(str(self.fields["Context1Salt"])))

        Context1DataLen = str(self.fields["Context1HashAlgoCount"])+str(self.fields["Context1SaltLen"])+str(self.fields["Context1HashAlgoType"])+str(self.fields["Context1Salt"])
        self.fields["Context1Len"] = struct.pack("<H",len(Context1DataLen))
        Context2Len = str(self.fields["Context2CipherCount"])+str(self.fields["Context2Cipher1"])+str(self.fields["Context2Cipher2"])
        self.fields["Context2Len"] = struct.pack("<H",len(Context2Len))

	####DialectCount....
        self.fields["DialectCount"] = struct.pack("<H", len(str(self.fields["Dialects"]))/2)


    def calculateFuzz(self, n =1):
       #Here we only fuzz length fields after the right calculation.
       fuzz = fuzzer()
       function=[
	{"NegoContextOffset":        		fuzz.DispatchPackets(self.fields["NegoContextOffset"])}, 
	{"NegoContextCount":        		fuzz.DispatchPackets(self.fields["NegoContextCount"])}, 
	{"DialectCount":        		fuzz.DispatchPackets(self.fields["DialectCount"])}, 
        {"Context1Len":               		fuzz.DispatchPackets(self.fields["Context1Len"])},
        {"Context1SaltLen":             	fuzz.DispatchPackets(self.fields["Context1SaltLen"])},
	{"Context2CipherCount":	   		fuzz.DispatchPackets(self.fields["Context2CipherCount"])},
        {"Context2Len":         		fuzz.DispatchPackets(self.fields["Context2Len"])},
        {"Context3Len":          		fuzz.DispatchPackets(self.fields["Context3Len"])},
        {"Context4Len":          		fuzz.DispatchPackets(self.fields["Context4Len"])},
     ]
       for i in range(n):
           result = choice(function)
           self.fields.update(result)
           print "CalculateFuzz updated this len in Nego Data:",result

    def PreFuzz(self, n =1):
        fuzz = fuzzer()
        function=[
	#{"Len":     	  		fuzz.DispatchPackets(self.fields["Len"])}, # in SMB2, fuzzing this len is irrelevant, just like wordcount in smbv1.
	#{"DialectCount":        		fuzz.DispatchPackets(self.fields["DialectCount"])}, #Already fuzzed in calculateFuzz()
	{"SecurityMode":     	 	fuzz.DispatchPackets(self.fields["SecurityMode"])},
	{"Capabilities":            	 	fuzz.DispatchPackets(self.fields["Capabilities"])},
	#{"Reserved":       	 	fuzz.DispatchPackets(self.fields["Reserved"])},
	{"Dialects":    	 	fuzz.DispatchPackets(self.fields["Dialects"])},
	{"Separator":            	 	fuzz.DispatchPackets(self.fields["Separator"])},
	{"Context1Type":           	 	fuzz.DispatchPackets(self.fields["Context1Type"])},
	{"Context1Reserved":        	 	fuzz.DispatchPackets(self.fields["Context1Reserved"])},
	{"Context1HashAlgoCount":            	 	fuzz.DispatchPackets(self.fields["Context1HashAlgoCount"])},
	{"Context1HashAlgoType":            	 	fuzz.DispatchPackets(self.fields["Context1HashAlgoType"])},
	{"Context1Salt":     		fuzz.DispatchPackets(self.fields["Context1Salt"])},
	{"Separator2": 		fuzz.DispatchPackets(self.fields["Separator2"])}, 
	{"Context2Type":    		fuzz.DispatchPackets(self.fields["Context2Type"])},
	{"Context2Reserved":		fuzz.DispatchPackets(self.fields["Context2Reserved"])},
	{"Context2CipherCount":	   		fuzz.DispatchPackets(self.fields["Context2CipherCount"])},
	{"Context2Cipher1":             fuzz.DispatchPackets(self.fields["Context2Cipher1"])},
	{"Context2Cipher2":		fuzz.DispatchPackets(self.fields["Context2Cipher2"])},
	{"Context4Data":		fuzz.DispatchPackets(self.fields["Context4Data"])},
	{"Context3NetName":		fuzz.DispatchPackets(self.fields["Context3NetName"])},
	{"Data":			fuzz.DispatchPackets(self.fields["Data"])},
     	]
	for i in range(n):
		result = choice(function)
		self.fields.update(result)
		print "Pre Fuzz updated this field in SMB2 Nego Data:",result


#######################Send packets##################################

def handle(data):

    #Nego SMB2
    if data[4:5] == "\xfe" and data[28:30]== "\x00\x00":
       h = SMBv2Header()
       h.PreFuzz(0)#SMBv2Header fuzz. set to 1 to fuzz it.
       n = SMB2Nego()#SMB2 nego command.
       n.PreFuzz(0)# we could fuzz some values like strings, then call calculate() and calculateFuzz(). set to 1 to fuzz it.
       n.calculate()
       n.calculateFuzz(0)# set this to 1 for one len fuzz.
       #What about calling PreFuzz() after we did all calculation instead of before? You get a different coverage, which is as interesting.
       n.PreFuzz(1) #1 = one entry point, 2= two entry point, etc.
       packet0 = str(h)+str(n) # Here we assemble the SMBv2 Header with the SMB2 Nego command
       buffer0 = longueur(packet0)+packet0 # we add the NBT Session len of the whole packet here.
       return buffer0 #send the packet.

    #Add Session Setup and more here...
   

def run(host):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(host)  
    s.settimeout(0.3)# Play with that for fuzzing speed. On good local network, it can be set to 0.1 without affecting the fuzzing session.
    h = SMBHeader(Cmd="\x72",Flag1="\x18",Flag2="\x53\xc8")
    n = SMBNego(Data = SMBNegoData())
    n.calculate()
    packet0 = str(h)+str(n)
    buffer0 = longueur(packet0)+packet0
    s.send(buffer0) # Here we send an SMBv1 Nego protocol (not our target in this exercise), and we send s.recv() to handle(), where fuzzing will be happening.
    try:
       while True:
         data = s.recv(1024)
         s.send(handle(data)) 
    except Exception:
         pass
         #raise #comment above "pass" and uncomment "raise" for debugging purposes.
         s.close()

if __name__ == "__main__":
    if len(sys.argv)<=1:
        sys.exit('Give me an IP Dude')
    host = sys.argv[1],445
    for x in range(100000):#adjust this value as needed..
       run(host)

