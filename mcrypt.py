#!/usr/bin/env python2

import string
import sys

print("Message Crypt")
print(" ")
print("USAGE: >> python mcrypt.py keyfile.txt")
print(" ")

print("Enter your message:")
keyfile = sys.argv[1]                           #Set ure keyfile
message = raw_input(">>")                               #User types message
message_split = message.split(" ")      #Split message into array
newmessage = []

def convert():
  for word in message_split[:]:         #For each word in message
    for line in open(keyfile,"r"):                      #Open line in file
      key_line = line.split(":")        #Split the line
      #print key_line[1]                        #Debug Print
      #print key_line[0]                        #Debug Print
      if word in key_line[0]:
        newmessage.append([key_line[1]])
      else:
        newmessage.append(word)

convert()
print newmessage
