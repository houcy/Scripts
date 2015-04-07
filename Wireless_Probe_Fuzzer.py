#!/usr/bin/env python2

from scapy.all import *

logfile = "wifiprobe.txt"
interface = "mon0"

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

banner()
target = raw_input("SSID> ")
for i in range(1,256):
  buffer_overflow = ["00"*i,"FF"*i]
  exploits = [buffer_overflow]
  for x in exploits[:]:
    tofuzz = [
    "Dot11Elt(ID=x,info='00')", 
    "Dot11Elt(ID='SSID', len=9,info=x)", 
    "Dot11Elt(ID='RATES', info=x)", 
    "Dot11Elt(ID='EXT RATES ',info=x)",  
    "Dot11Elt(ID='DS PARAM', info=x)",  
    "Dot11Elt(ID='COUNTRY', info=x)", 
    "Dot11Elt(ID='REQUEST',info=x)", 
    "Dot11Elt(ID='CHALLENGE TEXT ',info=x)", 
    "Dot11Elt(ID='POWER CONSTRAINT',info=x)", 
    "Dot11Elt(ID='POWER CAPAB ',info=x)", 
    "Dot11Elt(ID='CHANNELS',info=x)", 
    "Dot11Elt(ID='ERP INFO',info=x)", 
    "Dot11Elt(ID='ERP NONERP PRESENT',info=x)", 
    "Dot11Elt(ID='CHANNELS CHANNEL BAND',info=x)", 
    "Dot11Elt(ID='ERP BARKER LONG',info=x)", 
    "Dot11Elt(ID='RSN',info=x)", 
    "Dot11Elt(ID='VENDOR',info=x)", 
    "Dot11Elt(ID='COUNTRY TRIPLET',info=x)", 
    "Dot11Elt(ID='COUNTRY BAND TRIPLET',info=x)", 
    "Dot11Elt(ID='COUNTRY EXT TRIPLET',info=x)"]
    for a in tofuzz[:]:
      resp = hexdump(sendp(
        RadioTap()/
        Dot11(type=0,subtype=0100,addr2=target)/
        Dot11ProbeReq()/
        a))