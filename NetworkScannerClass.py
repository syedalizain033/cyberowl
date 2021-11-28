import os
from django.conf import settings


class NetworkScanner:
	def DNSLookUp(ip):
		dummy=ip
		
		command=" prips {0}  | ./hackdns".format(localIp)