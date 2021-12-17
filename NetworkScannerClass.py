import os
from django.conf import settings
from django.http import HttpResponse
from django.http import JsonResponse
import subprocess
import pandas as pd

class NetworkScanner:
    def DNSLookup(ip):

        dnsLookup = 'dnsLookup.txt'
        command = str(" prips {0}  | ./hackdns > " + dnsLookup).format(ip)
        os.system(command)
        file = open(dnsLookup)
        data = file.readline()
        data = tuple(data)
        return data

    def hostIP(ip):
        command = "host {0} > hostIP.txt".format(ip)
        os.system(command)
        file = open('hostIP.txt')
        content = file.readlines()
        return tuple(content)

    def activeScan(ip):

        command = "nmap -p- {0} | grep 'open' > activeScan.txt".format(ip)
        os.system(command)
        file = open('activeScan.txt')
        data = ["Scanning IP: " + ip + "\n"]
        for line in file.readlines():
            data.append(line)
        data = tuple(data)
        return data

    def intenseScan(ip):
        command = "nmap -sV -sC -p- {0} > intenseScan.txt".format(ip)
        os.system(command)
        file = open('intenseScan.txt')
        data = file.readlines()
        data = tuple(data)
        return data

    def CVEscanner(ip):
        command = "nmap -sV --script=vulscan/vulscan.nse  {0} > CVEscan.txt".format(
            ip)
        os.system(command)
        file = open("CVEscan.txt")
        content = file.readlines()
        content = tuple(content)
        return content

    def SuitableExploits(ip):
        command = "./suitableExploits.sh {0}".format(ip)
        os.system(command)
        file = open('suitableExploits.txt')
        data = file.readlines()
        data = tuple(data)
        return data

    def exploitLearner_2(ip):
        command = "ls ./exploits/vsftpd > exploits_list.txt"
        os.system(command)
        file = open('exploits_list.txt')
        content = file.readlines()
        for i in content:
            os.system('./exploits/vsftpd/{0} {1} > FTP.txt'.format(i, ip))
            file2 = open('FTP.txt')
            content2 = file2.readlines()
            if "Got Shell" in content2:
                return i




    def exploitLearner(ip):
    
        def check_existing_exploit(protocol,service,version):
            path = "./ai/self-learner.csv"
            if os.path.exists(path):
                df = pd.read_csv(path,header=None)
                df.columns = ['protocol','service','version','exploit']
                df = df[(df['protocol'] == protocol) & (df['service'] == service) & (df['version'] == version)]
                if len(df) > 0:
                    return df.iloc[0]['exploit']
                else:
                    return None 
    
        command = "nmap -sV -sC {} | grep open | grep -w ftp > intense_scan.txt".format(
            ip)
        os.system(command)
        _ = ""
        rows = []
        with open("intense_scan.txt", 'r') as F:
            _ = F.readlines()
            F.close()

        base_path = "./exploits/vsftpd"
        exploit_ = None
        
        for exploited_service in _:
            protocl = exploited_service.split()[-3]
            service = exploited_service.split()[-2]
            version = exploited_service.split()[-1]
            exploit_ = check_existing_exploit(protocl,service,version)
            if exploit_:
                rows.append(["{} - {} - {} can be exploited by {} (prediction)".format(protocl,service,version,exploit_)])


        if len(rows) > 0:
            return rows

        exploits = os.listdir(base_path)
        for exploit in exploits:
            if exploit.endswith(".py"):
                cmd = "python3 {} {}".format(
                    os.path.join(base_path, exploit), ip)
                
                
                
                
                output = subprocess.check_output(cmd, shell=True).decode("utf-8")
                print(output,type(output))

                if "Got Shell!!!" in output:
                    for exploited_service in _:
                        exploit_ = exploit
                        rows.append(
                            ",".join([protocl, service, version, exploit_]))
                        with open("./ai/self-learner.csv", 'a+') as ai_dump:
                            for row in rows:
                                ai_dump.write(row)
                                ai_dump.write("\n")
        return rows
    # def exploitLearner(ip):
    # 	command="nmap -sV {0} > learnerNmap.txt".format(ip)
    #
        #
        #
        # 	os.system(command)

    # 	#if "vsftpd" in result or result==result:
    # 	command="ls ./exploits/vsftpd > exploits_list.txt"
    # 	os.system(command)
    # 	file=open('exploits_list.txt')
    # 	content=file.readlines()
    # 	for i in content:
    # 		os.system('sh ./automateExploits.sh {0}'.format(ip))
    # 		file2=open('FTP.txt')
    # 		content2=file2.readlines()

    # 		if "Got Shell" in content2:
    # 			import csv
    # 			header=['service','version','exploit']
    # 			data=[['FTP','2.3.4',i]]
    # 			with open ('exploits.csv', 'w', encoding='UTF8', newline='') as f:
    # 				writer=csv.writer(f)
    # 				writer.writerow(header)
    # 				writer.writerows(data)
    # 				return 'exploit_1.py'

    # 	return "exploit_1.py"

    def NetworkFullyScanner(ip):
        a = 1  # dummy for now. To be edited.
