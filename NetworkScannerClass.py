import os 
from django.conf import setting

class NetworkScanner:
	def DNSLookup(ip):
		command=" prips {0}  | ./hackdns".format(ip)
		data=os.system(command)
		return data
	

	def hostIP(ip):
		command="host {0} > hostIP.txt".format(ip)
		file=open('hostIP.txt')
		content=file.readlines()
		return tuple(content)


	def NetworkFullyScanner(ip):
		a=1 #dummy for now. To be edited. 