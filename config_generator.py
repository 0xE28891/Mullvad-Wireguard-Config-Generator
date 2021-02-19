"""
Usage: python3 config_generator.py

Fetches all Wireguard servers from Mullvad's public API
Generates a wireguard .conf file for each Wireguard server
that Mullvad has available.

Config files are saved to /etc/wireguard/mullvad
"""

import pathlib
import requests
import os

MULLVAD_SERVER_LIST_ENDPOINT = "https://api.mullvad.net/www/relays/all/"
ADDRESS = "10.66.166.115/32"
PRIVATE_KEY = ""
DNS = "193.138.218.74"
IPTABLES = "Table = 55111\n\nPostUp = iptables -t nat -A POSTROUTING -o %i -j MASQUERADE\nPostUp = iptables -I FORWARD -i vpn0 -o %i -j ACCEPT\nPostUp = ip rule add from 10.10.10.0/24 lookup 55111\nPostUp = ip rule add lookup main suppress_prefixlength 0\nPreDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE\nPreDown = ip rule del lookup main suppress_prefixlength 0\nPreDown = ip rule del from 10.10.10.0/24 lookup 55111"
FILE_ILLEGAL_CHARS = r"/?:\<>*|#, "

CONFIG_DIRECTORY = f"/etc/wireguard/mullvad"

def sanitise_string(text): #removes all characters that are illegal in windows filenames
    return text.translate({ord(c): None for c in FILE_ILLEGAL_CHARS})

def remove_all_files_in_directory(directory): #removes all FILES in a given directory
    for root, dirs, files in os.walk(directory):
        for file in files:
            os.remove(os.path.join(root, file))

def save_config_to_file(jsondata): #given a server json, make a config file from it
    servername = jsondata.get('hostname').replace("-wireguard", "")
    #city_code = jsondata.get('city_code')
    city_code = jsondata.get('city_name')
    provider = jsondata.get('provider')

    filename = f"mullvad-{servername}.conf"
    filename = sanitise_string(filename)
    configstring = generate_wireguard_config(jsondata)

    with open(f"{CONFIG_DIRECTORY}/{filename}", "w", encoding="utf-8") as outfile:
        outfile.write(f"{configstring}")

def generate_wireguard_config(jsondata): #generates a wireguard config string, given a server json
    configstring = "[Interface]\n"
    configstring += f"PrivateKey = {PRIVATE_KEY}\n"
    configstring += f"Address = {ADDRESS}\n"
    configstring += f"DNS = {DNS}\n"
    configstring += f"{IPTABLES}\n\n"
    configstring += "[Peer]\n"
    configstring += f"PublicKey = {jsondata['pubkey']}\n"
    configstring += "AllowedIPs = 0.0.0.0/0\n"
    configstring += f"Endpoint = {jsondata['ipv4_addr_in']}:51820\n"
    
    return configstring

if __name__ == "__main__":
    pathlib.Path(f"{CONFIG_DIRECTORY}").mkdir(parents=True, exist_ok=True)
    remove_all_files_in_directory(CONFIG_DIRECTORY) #remove all old config files

    server_data_request = requests.get(MULLVAD_SERVER_LIST_ENDPOINT, timeout=(11,30))
    server_data_request.raise_for_status()

    server_data = server_data_request.json()

    for item in server_data:
        active_status = item.get("active")
        owned_status = item.get("owned")
        server_type = item.get("type")
        country_code = item.get("country_code")     
        
        
        if active_status == True and owned_status == True and server_type == "wireguard" and country_code != "au" and country_code != "br" and country_code != "ca" and country_code != "gb" and country_code != "hk" and country_code != "jp" and country_code != "nz" and country_code != "sg" and country_code != "us":
            save_config_to_file(item)

    print(f"Saved config files to {CONFIG_DIRECTORY}")
