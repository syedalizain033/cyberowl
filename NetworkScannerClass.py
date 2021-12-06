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
			

	def CVEscanner(ip):
		command="nmap -sV --script=vulscan/vulscan.nse  {0} > CVEscan.txt".format(ip)
		os.system(command)
		file=open("CVEscan.txt")
		content=file.readlines()
		content=tuple(content)
		return content


	def SuitableExploits(ip):
		command="./suitableExploits.sh {0}".format(ip)
		os.system(command)
		file=open('suitableExploits.txt')
		data=file.readlines()
		data=tuple(data)
		return data

	def exploitLearner_2(ip):
		command="ls ./exploits/vsftpd > exploits_list.txt"
		os.system(command)
		file=open('exploits_list.txt')
		content=file.readlines()
		for i in content:
			os.system('./exploits/vsftpd/{0} {1} > FTP.txt'.format(i, ip))
			file2=open('FTP.txt')
			content2=file2.readlines()
			if "Got Shell" in content2:
				return i
			


	def exploitLearner(ip):
		command="nmap {0} > learnerNmap.txt".format(ip)
		os.system(command)
		
		#if "vsftpd" in result or result==result:
		command="ls ./exploits/vsftpd > exploits_list.txt"
		os.system(command)
		file=open('exploits_list.txt')
		content=file.readlines()
		for i in content:
			os.system('sh ./automateExploits.sh {0}'.format(ip))
			file2=open('FTP.txt')
			content2=file2.readlines()
			
			if "Got Shell" in content2:
				import csv
				header=['service','version','exploit']
				data=[['FTP','2.3.4',i]]
				with open ('exploits.csv', 'w', encoding='UTF8', newline='') as f:
					writer=csv.writer(f)
					writer.writerow(header)
					writer.writerows(data)
					return 'exploit_1.py'

		
		return "exploit_1.py"
    			


	 



	def NetworkFullyScanner(ip):
		a=1 #dummy for now. To be edited. 