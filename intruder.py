#!/usr/bin/env python2

from scapy.all import *
import sys
import telnetlib
import string
import threading

target        = sys.argv[1]
port          = sys.argv[2]
logfile       = sys.argv[3]
commandlist   = sys.argv[4]

command = []

#Setup banner
def usage():
  print("Intruder v1.1")
  print("")
  print("Usage:")
  print(" ")
  print(" >> python2 intruder.py (host) (port) (log file) (command file) (response file) (type)")
  print(" ")

#Define the response analysis
def response_analyse(resp,fuzz):
  
  if "AAA41" in resp:
    ee = hexdump(resp)
    with open(logfile, "a") as myfile:
      myfile.write("Port "+str(port)+" "+"String: "+str(fuzz)+"\n"+str(ee)+"\n")
    print("Potential vuln")
    print(fuzz)
    hexdump(resp)

  if "PATH=" in resp:
    ee = hexdump(resp)
    with open(logfile, "a") as myfile:
      myfile.write("Port "+str(port)+" "+"String: "+str(fuzz)+"\n"+str(ee)+"\n")
    print("Potential vuln")
    print(fuzz)
    hexdump(resp)

  if "segmentation" in resp:
    ee = hexdump(resp)
    with open(logfile, "a") as myfile:
      myfile.write("Port "+str(port)+" "+"String: "+str(fuzz)+"\n"+str(ee)+"\n")
    print("Potential vuln")
    print(fuzz)
    hexdump(resp)

  if "core" in resp:
    ee = hexdump(resp)
    with open(logfile, "a") as myfile:
      myfile.write("Port "+str(port)+" "+"String: "+str(fuzz)+"\n"+str(ee)+"\n")
    print("Potential vuln")
    print(fuzz)
    hexdump(resp)

#Define the engine
def engine(target,port,command):

  for i in range(1,10000):
    format_strings   = ["AAA%08$x","AAA%08%h","AAA%08$s","AAA%08$n","%s"*i,"AAA%080$u"]
    buffer_overflows = ["00"*i,"FF"*i,"%"*i]
    remote_code      = ["set","'set",":set","|set","$set"]
    integer_overflow = [str(i)*i]
    exploits         = [format_strings,buffer_overflows,remote_code,integer_overflow]
    for c in command[:]:
      for exp in exploits[0:]:
        for ex in exp[:]:
          for g in range(1,10):  
            gen = ex+" "
            fuzz = str(c[:])+' '+gen*g+'\n'
            tn = telnetlib.Telnet(target,port)
            tn.read_until("\r\n")			# --uncomment for FTP
            print("Sending "+fuzz)
            tn.write(fuzz)
            d = tn.read_until("\r\n")
            hexdump(d)
            response_analyse(d,fuzz)
               
if "ftp" == commandlist:
  command = ["USER ","PASS ", "CDUP ","SMNT ","STOU ","XSEN ","XSEM ,","XRSQ ","XRMD ","XRCP ","XPWD ","XMKD ","XCUP ","LANG ","FEAT ","EPSV ","ADAT ",
  "STRU ","STAT ","SIZE ","SITE ","RNTO ","RNFR ","RMD ","RETR ","REST ","PROT ","PBSZ ","OPTS ","NLST ","MLST ","MLSD ","MIC ","LPRT ", "EPRT ","CCC ",
  "RMD ","MKD ","PWD ","SYST ","REIN ","PORT ","PASV ","TYPE","MODE ","RETR", "STOR ","APPE ","ALLO ","REST ","RNFR ","MDTM ","LPSV ","ENC ","CONF ","CDUP "]
  engine(target,port,command)

elif "pop3" == commandlist:
  command = ["POP3: ","USER ","PASS ","QUIT ","STAT ","RETR ","DELE ","NOOP ","LAST ","RSET ","TOP ","RPOP "]
  engine(target,port,command)

elif "http" == commandlist:
  command = ["HTTP: ","GET /","HEAD /","PUT /","TRACE /","DELETE /","LINK /","UNLINK /", "CONNECT","request-header "] 
  engine(target,port,command)

else:
  for line in open(commandfile,"r"):
    command.append(line)
    engine(target,port,command)

