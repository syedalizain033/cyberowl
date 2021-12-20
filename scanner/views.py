from django.http import HttpResponse
from django.shortcuts import redirect, render

from NetworkScannerClass import NetworkScanner
from .forms import IPScannerForm, WebAttackForm, WebScannerForm
from scanner.Network_Scanner.Hosted_Website import Hosted_Website
import re
import os
from django.conf import settings



def home(request):
    return render(request, "scanner/home.html")

#-----------------------------------------------------------------------------------
def scan(request):
    return render(request, 'scanner/scanner.html')

#def downloadWayback(request):
#    from downloadFile import Downloader
#    download = Downloader
#    response=download.downloadWayBackFile()
#    return response
#------------------------------------------------------------------------------------
def ip_scanner(request):
    form = IPScannerForm(request.POST)
    if request.method=="POST" and form.is_valid() :
        from NetworkScannerClass import NetworkScanner
        obj=NetworkScanner   
        '''
        scanTypes =( ("1", "DNS Look Up"), ("2", "Hosted Website"), ("3", "Port Knocking"),
        ("4", "Active Network Scan"), ("5", "Intense Network Scan"), )
        '''  
        ip=form.cleaned_data['ip']
        ip=str(ip)
        choice=form.cleaned_data['choice']
        
        #choice=scanTypes[int(choice)-1][1]
        #data=str(ip)+" "+str(choice)
        if  (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)):
            if choice=="1":
                data=obj.hostIP(ip)
                return render(request, 'scanner/scanning_ip.html',{'data':data})

            if choice=="2":
                data=obj.hostIP(ip)
                return render(request, 'scanner/scanning_ip.html',{'data':data})
                
            if choice=="3":
                data=obj.activeScan(ip)
                return render(request, 'scanner/scanning_ip.html',{'data':data})

            if choice=="4":
                data=obj.intenseScan(ip)
                return render(request, 'scanner/scanning_ip.html',{'data':data})

            if choice=="5":
                data=obj.CVEscanner(ip)
                return render(request, 'scanner/scanning_ip.html',{'data':data})

            if choice=="6":
                data=obj.SuitableExploits(ip)
                return render(request, 'scanner/scanning_ip.html',{'data':data})

            if choice=="7":
                data=obj.exploitLearner(ip)
                #data="exploit_1"
                return render(request, 'scanner/scanning_ip.html',{'data':data})

            



            #else:
            #    form=IPScannerForm()
            #    return render(request, 'scanner/scanning_ip.html',{'error':"Invalid IP Address.", 'form':form,})

        else:
            form=IPScannerForm()
            return render(request, 'scanner/scanning_ip.html',{'error':"Invalid IP Address.", 'form':form,})
    else:
        form=IPScannerForm()
        return render(request, 'scanner/ip_scanner.html', {'form':form})

#------------------------------------------------


def self_learn(request):


    from NetworkScannerClass import NetworkScanner
    obj=NetworkScanner
    data = obj.viewLearntData

    if isinstance(data, tuple):
        return render(request, 'scanner/self_learn.html', {'data': data})
    elif isinstance(data, str):
        string=str(data)
        return render(request, 'scanner/self_learn.html', {'string': string})
    else:
        return render(request, 'scanner/self_learn.html', {'string': data})



#--------------------------------------------------------------------------------
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
        print(discovered_subdomains[2])
        return discovered_subdomains


def urlIsValid(url): #this function will take url as param, would check if the url matches the pattern.
    #the pattern is http://site.com or http://www.site.com   It returns true or false.
    import re
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    x=(re.match(regex, url) is not None)
    return x

def webCut(url): #removes www https:// etc and returns url string type
    import re
    reurl = re.compile(r"https?://(www\.)?")
    returnUrl = reurl.sub('', url).strip().strip('/')
    return returnUrl

def webscanner(request):
    #scanTypes=(('1','Sub-Domains Enumeration'), 
    # ('2','Sub-Domains of Sub-Domains'), ('3','WayBack Scan'),('4', 'Other sites on domain'),('5', 'Every Link On SearchEngine'),)

    if request.method=="POST":
        form=WebScannerForm(request.POST)
        if form.is_valid():
            import requests as r
            webUrl = form.cleaned_data['webUrl']
            '''if (urllib.request.urlopen(webUrl).getcode()!=200):
                return render(request, 'scanner/webscan_results.html', {
                    'type':"Invalid web url. Web Url not working."
                })
'''
            
            validUrl=urlIsValid(webUrl)
            if validUrl==False:
                warning="Invalid URL Pattern. Please follow this pattern. 'http://www.site.com'"
                return render(request, 'scanner/webscan_results.html', {'warning': warning})
            if validUrl==True:
                webUrl=webCut(webUrl)
                choice = str(form.cleaned_data['choice'])
                from WebScannerClass import WebScannerClass 
                obj=WebScannerClass 

                if choice=="1":
                    
                    subdomains = obj.intenseSubdomainEnumeration(webUrl)
                    data=subdomains
                    type="Subdomains of {0}".format(str(webUrl))
    #                print(type(data))
                    subdomains=tuple(data)
                    #data = webUrl+" "+choice
                    return render(request,'scanner/webscan_results.html', {
                        'subdomains': subdomains, 'type': type
                        })

                #wayback urls
                if choice == "3" or choice=="5": 
                    wayback = obj.wayBackUrls(webUrl)
                    type="All Links of {0}".format(str(webUrl))
                    jsLinks=[]
                    pyfiles=[]
                    waybacklist=list(wayback)
                    for i in waybacklist:
                        if i[-3:] == ".js": #collecting JS files
                            jsLinks.append(i)
                        elif i[-3:]==".py": #collect Py Files if found and critical
                            pyfiles.append(i)

                    data = tuple(wayback)
                    jsLinks=tuple(jsLinks)
                    pyfiles=tuple(pyfiles)
                    type="All urls of {0}".format(str(webUrl))
                    print(data)
                    return render(request,'scanner/webscan_results.html', {'wayback': tuple(wayback), 
                    'type':type, 'jsLinks':jsLinks })
    else:
        form=WebScannerForm()
        return render(request, 'scanner/web_scanner.html', {'form':form})
#----------------------------------------------------------------------



#----------------------------------------------------------------------

#def convertIntoPdf(request):
#    from fpdf import FPDF
#    pdf = FPDF()   
#    pdf.add_page()
#    pdf.set_font("Arial", size = 15)
#    f = open("myfile.txt", "r")
#    for x in f:
#        pdf.cell(200, 10, txt = x, ln = 1, align = 'C')
#      pdf.output("mygfg.pdf") 

def contact(request):
    
    return render(request, 'scanner/contact_us.html')

#---------------Attacking--------------------------------

def webattack(request):
    from WebScannerClass import WebScannerClass 
    obj=WebScannerClass
    if request.method=="POST":
         
        form=WebAttackForm(request.POST)
        if form.is_valid():
            weburl=form.cleaned_data['attackurl']
            isValidUrl=urlIsValid(weburl)
            if isValidUrl==True:
                
                attacktype=form.cleaned_data['attacktype']
                if attacktype=="1": #git leakage attack
                    if "github.com/" in weburl:
                        
                        
                        data=obj.gitLeaks(weburl)
                        return render(request, 'scanner/webattackresults.html', {'data':data})
                    
                        
                    else:
                            error="Invalid URL. Please Enter Github URL if scanning for Git Leaks. "
                            return render(request, 'scanner/webattackresults.html', {'error':error})
                if attacktype=="2": #sql injection
                   # if "=" in weburl:
                    data = obj.sqlInjection(weburl)
                    return render(request, 'scanner/webattackresults.html', {'data':data})

                if attacktype=="3": # Intense Attack
                    weburl=webCut(weburl)
                    x=obj.intenseWebScanningAttack(weburl)
                    if x==True:
                        return render(request, 'scanner/webattackresults.html', {'warning': "Intense scan attack done. Please check your desktop."})



            if isValidUrl==False:
                warning="Please enter a valid format URL. Example: http://example.com"
                return render(request, 'scanner/webattackresults.html', {'warning':warning})

    else:
            
        form=WebAttackForm()
        return render (request, 'scanner/webattack.html', {'form':form})