from typing import AsyncContextManager

from django import forms
from django.forms import ModelForm, widgets


class IPScannerForm(forms.Form):
    scanTypes =( ("1", "DNS Look Up"), ("2", "Hosted Website"), ("3", "Port Knocking"), 
("4", "Active Network Scan"), ("5", "Intense Network Scan"), )
    ip=forms.CharField(max_length=15, required=True, label="IP Address")
    choice=forms.ChoiceField(choices=scanTypes, required=True)


class WebScannerForm(forms.Form):
    webUrl=forms.CharField(max_length=500, required=True, label="Web Url")
    scanTypes=(('1','Sub-Domains Enumeration'), ('2','Sub-Domains of Sub-Domains'), ('3','WayBack Scan'),('4', 'Other sites on domain'),('5', 'Every Link On SearchEngine'),)
    choice=forms.ChoiceField(choices=scanTypes, required=True)

class WebAttackForm(forms.Form):
    AttackTypes=(('1', 'XSS Attack'),('2','SQL Injection'),)
    attackurl=forms.CharField(max_length=1000, required=True, label="URL")
    attacktype=forms.ChoiceField( choices=AttackTypes, required=True)