import os
import socket
import subprocess
import geoip2.database
from ipwhois import IPWhois
import ipaddress
import requests
import whois
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def print_breaches(breaches):
    for breach in breaches:
        print("Name:", breach['Name'])
        print("Title:", breach['Title'])
        print("Domain:", breach['Domain'])
        print("Breach Date:", breach['BreachDate'])
        print("Description:", breach['Description'])
        print("Pwn Count:", breach['PwnCount'])
        print("------------------------------------------")

def check_breaches():
    ip_address = input("Enter IP address: ")
    url = f"https://haveibeenpwned.com/api/v2/breaches?ipAddress={ip_address}"
    print("Checking breaches for IP:", ip_address)
    response = requests.get(url)
    if response.status_code == 200:
        breaches = response.json()
        print_breaches(breaches)
        return breaches
    else:
        print("Failed to fetch breaches. Status code:", response.status_code)
        return None

def print_whois_info(whois_info):
    for key, value in whois_info.items():
        if isinstance(value, dict):
            print(f"{key}:")
            print_whois_info(value)
        elif value is None:
            print(f"{key}: None")
        else:
            print(f"{key}: {value}")

def ip_whois_lookup():
    ip_address = input("Enter IP address: ")
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()
        print("IP Address:", ip_address)
        print("WHOIS Information:")
        print_whois_info(results)
    except Exception as e:
        print("An error occurred:", e)

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

def scan_local_network():
    local_ip = get_local_ip()
    network_prefix = '.'.join(local_ip.split('.')[:-1]) + '.'

    connected_ips = []

    for i in range(1, 255):
        ip = network_prefix + str(i)
        response = subprocess.call(['ping', '-c', '1', ip])
        if response == 0:
            connected_ips.append(ip)

    return connected_ips

def ip_range_search():
    start_ip = input("Enter start IP: ")
    end_ip = input("Enter end IP: ")
    try:
        start_ip_obj = ipaddress.ip_address(start_ip)
        end_ip_obj = ipaddress.ip_address(end_ip)

        if start_ip_obj.version != end_ip_obj.version:
            print("IP versions mismatch")
            return
        
        ip_range = list(ipaddress.summarize_address_range(start_ip_obj, end_ip_obj))
        ip_list = [ip for subnet in ip_range for ip in subnet]

        print("IP addresses within the range:")
        for ip in ip_list:
            print(ip)
    except ValueError:
        print("Invalid IP address")

def get_network_info():
    ip_address = input("Enter IP address: ")
    obj = IPWhois(ip_address)
    result = obj.lookup_rdap()

    asn = result['asn']
    asn_description = result['asn_description']
    cidr = result['network']['cidr']

    print("Autonomous System Number (ASN):", asn)
    print("ASN Description:", asn_description)
    print("CIDR Range:", cidr)

def geolocate():
    ip_address = input("Enter IP address: ")
    try:
        reader = geoip2.database.Reader('/usr/lib/gophish/static/db/geolite2-city.mmdb')  
        response = reader.city(ip_address)
        country = response.country.name
        city = response.city.name
        latitude = response.location.latitude
        longitude = response.location.longitude
        print("Country:", country)
        print("City:", city)
        print("Latitude:", latitude)
        print("Longitude:", longitude)
    except (FileNotFoundError, geoip2.errors.AddressNotFoundError):
        print("Error: Unable to geolocate IP address.")

def website_ip():
    website = input("Enter website URL (www.example.com): ")
    try:
        ip_address = socket.gethostbyname(website)
        print("IP Address:", ip_address)
    except socket.gaierror:
        print("Error: Unable to resolve hostname.")

def ascii():
    print(RED + " (    (        (        )      )      )        (     ")
    print(" )\ ) )\ )     )\ )  ( /(   ( /(   ( /(        )\ )  ")
    print("(()/((()/(    (()/(  )\())  )\())  )\())   (  (()/(  ")
    print(" /(_))/(_))    /(_))((_)\  ((_)\ |((_)\    )\  /(_)) ")
    print("(_)) (_))     (_))    ((_)   ((_)|_ ((_)_ ((_)(_))   ")
    print("|_ _|| _ \    | |    / _ \  / _ \| |/ /| | | || _ \  ")
    print(" | | |  _/    | |__ | (_) || (_) | ' < | |_| ||  _/  ")
    print("|___||_|      |____| \___/  \___/ _|\_\ \___/ |_|    " + RESET)

def main():
    ascii()
    print(YELLOW + "1. Configure Website IP\n2. IP Geolocation\n3. See Network Info\n4. IP Range Search\n5. Scan Local Network\n6. WHOIS Lookup(Might not be correct)\n7. IP Breach Check(Cause ip addresses change due to the local network it might be not you who was in the breach)\n" + RESET)
    choice = input("Enter> ")
    try:
        choice = int(choice)
        if choice == 1:
            website_ip()
        elif choice == 2:
            geolocate()
        elif choice == 3:
            get_network_info()
        elif choice == 4:
            ip_range_search()
        elif choice == 5:
            scan_local_network()
        elif choice == 6:
            ip_whois_lookup()
        elif choice == 7:
            check_breaches()
        else:
            print("Invalid choice!")
    except ValueError:
        print("Invalid choice! Please enter a number.")

if __name__ == "__main__":
    main()


