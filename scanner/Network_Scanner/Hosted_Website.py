class Hosted_Website:
    def hosted_website(ip):
        import socket as sock
        
        site=sock.gethostbyaddr(ip)
