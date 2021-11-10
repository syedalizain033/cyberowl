from django.urls import path
from scanner import views

urlpatterns = [
    path("", views.home, name="home"),
    path("home", views.home, name='home'),
    path("home/", views.home, name='home'),
    path('scan', views.scan, name='scan'),
    path("scan/", views.scan, name='scan'),
    path('contact/', views.contact, name='contact'),
    path("contact", views.contact, name='contact'),
    path("ipscan/", views.ip_scanner, name='ip_scanner'),
    path("ipscan", views.ip_scanner, name='ip_scanner'),
    path("webscan/", views.webscanner, name="webscanner"),
    path("webscan", views.webscanner, name="webscanner"),
    path('<str:filepath>/',views.downloadWayback, name='downloadWayback')
    
]