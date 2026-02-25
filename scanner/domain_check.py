import socket

def check_ip_url(domain):
    try:
        socket.inet_aton(domain)
        return True   # It is an IP address
    except:
        return False  # It is a normal domain
