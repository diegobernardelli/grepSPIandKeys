#!/usr/bin/env python3
import re
import sys


def rfcReverse(regexResult):

	alg = regexResult[0][1]

	if alg == "aes":
		#"IPv4","","","","AES-CBC [RFC3602]","","HMAC-SHA-256-128 [RFC4868]",""
		return '"IPv4","*","*","0x'+regexResult[0][0]+'","AES-CBC [RFC3602]","0x'+regexResult[0][3]+'","HMAC-SHA-256-128 [RFC4868]","0x'+regexResult[0][6]+'"'
	elif alg == "aes-gcm":
		#enc: spi=758f7b25 esp=aes-gcm key=20 7c87683b76e00b54370e1a9634c6e52f901c71f8 ah=null key=0
		#"IPv4","","","","AES-GCM [RFC4106]","","NULL",""
		return '"IPv4","*","*","0x'+regexResult[0][0]+'","AES-GCM [RFC4106]","0x'+regexResult[0][3]+'","NULL",""'
	elif alg == "des":
		#"IPv4","","","","DES-CBC [RFC2405]","","NULL",""
		#enc: spi=758f7b2b esp=des key=8 9062713a8e8de11b ah=sha256 key=32 b2007e5f8c890ab8524428ec3437be15cdade74a2b5efaaa69df751c574caae3
		return '"IPv4","*","*","0x'+regexResult[0][0]+'","DES-CBC [RFC2405]","0x'+regexResult[0][3]+'","HMAC-SHA-256-128 [RFC4868]","0x'+regexResult[0][6]+'"'
	elif alg == "3des":
		#enc: spi=758f7b28 esp=3des key=24 22c375fa045737087f62a7fd41aba223e70721c5bd420cde ah=sha256 key=32 16099f57e27256c1104a7daf137d6960b4072258685a29f101a4dc493122f275
		#"IPv4","","","","TripleDES-CBC [RFC2451]","","NULL",""
		return '"IPv4","*","*","0x'+regexResult[0][0]+'","TripleDES-CBC [RFC2451]","0x'+regexResult[0][3]+'","HMAC-SHA-256-128 [RFC4868]","0x'+regexResult[0][6]+'"'
	else:
		return "algorithm not found"


rfile = open(sys.argv[1], "r")
file = rfile.read().splitlines()

#print(file)
pattern = "enc: |dec: "

i=0
j=1
rawlist=[]

#get each VPN tunnels, get each pair of lines for encryption or decryption SPI and keys (x2)
#put everything into a list with all unsorted entries
while i < len(file):
	if re.search(pattern, file[i]):
		#print (">>> Line,Instance= ", i, ",", j, sep='')
		#print (">>>", file[i].strip(), "<< -- >>", file[i+1].strip())
		rawlist.append(str(file[i].strip()+" "+file[i+1].strip()))
		j+=1

		#print (file[i].strip()+file[i+1].strip())
	i+=1


print("\nTO BE CUT AND PASTED IN YOUR ESP SA\'S CONFIG FILE IN WIRESHARK 4.0.4+")

i=0 
for item in rawlist: 
	# fileds in item to look for: 
	# 1- enc:|dec:          e.g. dec:
	# 2- spi=[a-f0-9]*      e.g. spi=2ea5d1ea
	# 3- esp=[a-z0-9]*      e.g. esp=aes
	# 4- key=[0-9]*         e.g. key=32
	# 5- [a-f0-9]*          e.g. c4f123ca3819c3df04a39e8793fadeacc51c3b9ddb4560c81dfc7019689008ac
	# 6- ah=[a-z0-9]*       e.g. ahsha256
	# 7- key=[0-9]*         e.g. key=32
	# 8- [a-f0-9]*          e.g. 98459d0c75354883c94668ebdcd0af710ba23665fbb345c89362438fb76a6751
	#print(item) 
	reRes = re.findall('spi\=(\w+)\sesp\=(\S+)\skey\=([0-9]+)\s(\w+)\sah\=(\w+)\skey\=([0-9]*)\s?(\w+)?',item)
	# no need to increment i as rematching in next loop
	#print(reRes)

	parsedOutput = rfcReverse(reRes)
	print(parsedOutput)




	
