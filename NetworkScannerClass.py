import os 
from django.conf import settings

class NetworkScanner:
	def DNSLookup(ip):
		
		dnsLookup = 'dnsLookup.txt'
		command=str(" prips {0}  | ./hackdns > " + dnsLookup).format(ip)
		os.system(command)
		file=open(dnsLookup)
		data=file.readline()
		data=tuple(data)
		return data

	def hostIP(ip):
		command="host {0} > hostIP.txt".format(ip)
		os.system(command)
		file=open('hostIP.txt')
		content=file.readlines()
		return tuple(content)


	def activeScan(ip):
    		
		command="nmap -p- {0} | grep 'open' > activeScan.txt".format(ip)
		os.system(command)
		file=open('activeScan.txt')
		data = ["Scanning IP: " + ip + "\n"]
		for line in file.readlines():
			data.append(line)
		data=tuple(data)
		return data


	def intenseScan(ip):
		command="nmap -sV -sC -p- {0} > intenseScan.txt".format(ip)
		os.system(command)
		file=open('intenseScan.txt')
		data=file.readlines()
		data=tuple(data)
		return data
			

	 



	def NetworkFullyScanner(ip):
		a=1 #dummy for now. To be edited. 