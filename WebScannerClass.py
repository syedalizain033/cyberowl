
import os 
from django.conf import settings


class WebScannerClass:
    
    def subDomainsEnumeration(inputWeb): # Returns list of subdomains
        import requests
        import requests as req
        domain=inputWeb
        file = open(os.path.join(settings.BASE_DIR, 'subdomains-10000.txt'))
#        file=open('subdomains-10000.txt')
        content=file.read()
        subdomains=content.splitlines()
        discovered_subdomains=[]
        for subdomain in subdomains:
            url=f"http://{subdomain}.{domain}"
            try:
                req.get(url)
            except req.ConnectionError:
                pass
            else:
                discovered_subdomains.append(url)
        return tuple(discovered_subdomains)


    def nextLevelSubDomains(inputWeb):
        
        import requests as req
        domain=inputWeb
#        file = open(os.path.join(settings.BASE_DIR, 'subdomains-10000.txt'))
        file=open('subdomains-10000.txt')
        content=file.read()
        subdomains=content.splitlines()
        discovered_subdomains=[]
        for subdomain in subdomains:
            url=f"http://{subdomain}.{domain}"
            try:
                req.get(url)
            except req.ConnectionError:
                pass
            else:
                discovered_subdomains.append(url)
        return tuple(discovered_subdomains)


    def intenseSubdomainEnumeration(weburl): #returns subdomains as list 'discovered_subdomains' with assetfinder
        OScommand=("echo '{0}' | ./subdomain_finding > asset.txt").format(weburl)
        import os
        os.system(OScommand)
        file=open('asset.txt')
        content=file.readlines()
        discovered_subdomains=[]
        for i in content:
            discovered_subdomains.append(str(i))
        tup=tuple(discovered_subdomains)
        return discovered_subdomains


    def wayBackUrls(weburl):
        OScommand = ("echo '{0}' | ./waybackurls > waybackurls.txt").format(weburl)
        os.system(OScommand)
        file=open('waybackurls.txt')
        content=file.readlines()
        discovered_subdomains=[]
        for i in content:
            discovered_subdomains.append(str(i))
        tupleData=tuple(discovered_subdomains) # Django sends tuples as dynamic data to templates.
        return tupleData


    def gitLeaks(weburl):
        OScommand=("./git-secret {0} > gitleaks.txt").format(weburl)
        os.system(OScommand)
        file=open('gitleaks.txt')
        content=file.readlines()
        content=tuple(content)
        return content

    def sqlInjection(weburl):
        OScommand=("echo {0} | sqlmap --dbs > sqlmap.txt").format(weburl)
        os.system(OScommand)
        file=open('sqlmap.txt')
        content=file.readlines()
        data=[]
        for i in content:
            if "starting @" in i:
                data.append(i)
            if "GET " in i:
                data.append(i)
            if "testing URL" in i:
                data.append(i)
            if "Payload" in i:
                data.append(i)
            if "retrieved" in i:
                data.append(i)

        content=tuple(content)
        return content


