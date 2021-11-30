#! /bin/bash
echo "Tester Owl scanning $1"
nmap -sV -sC -p- $1 > nmap_scan.txt
