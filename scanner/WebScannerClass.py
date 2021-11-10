



from io import IncrementalNewlineDecoder


class WebScannerClass:
    
    def subDomainsEnumeration(inputWeb): # Returns list of subdomains
        import requests
        import requests as req
        domain=inputWeb
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
        return discovered_subdomains


    def intenseSubdomainEnumeration(inputWeb): #returns subdomains as list 'discovered_subdomains' with assetfinder
        OScommand=("echo '{0}' | subdomain_finding > asset.txt").format(inputWeb)
        
        domain=inputWeb
        #including bash in the code
        import os
        os.system(OScommand)
        file=open('asset.txt')
        content=file.readlines()
        discovered_subdomains=[]
        for i in content:
            discovered_subdomains.append(str(i))
        #print(discovered_subdomains[2])
        return discovered_subdomains
