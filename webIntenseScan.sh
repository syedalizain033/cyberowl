#! /bin/bash
echo "Tester Owl web intense scanner"
cd
path=$(pwd) 
cd Desktop
mkdir TesterOwl && cd TesterOwl
echo $1 | $path/subdomain_finding > subdomains.txt
for sub in $(cat subdomains.txt)
do 
mkdir $sub
echo $sub | $path/waybackurls > $sub/waybackurls.txt 
cat $sub/waybackurls.txt | grep '/api/' > $sub/apiEndPoints.txt
cat $sub/waybackurls.txt | grep '.json' > $sub/jsonFiles.txt
nikto -h $sub -C all > $sub/niktoScan.txt
done


