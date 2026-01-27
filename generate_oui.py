import requests
import re
import csv
from colorama import Fore, Back, Style

# URL IEEE
URL = "http://standards-oui.ieee.org/oui.txt"
OUTPUT_FILE = "oui.csv"

def download_and_parse():
    print(Style.BRIGHT + Fore.BLACK + Back.YELLOW + f"Downloading database from {URL}...")
    try:
        response = requests.get(URL)
        response.raise_for_status()
    except Exception as e:
        print(Back.RED + f"Error: {e}")
        return

    print(Back.YELLOW + "Download completed. I'm now refactoring the data...")
    
    regex = re.compile(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)$', re.MULTILINE)
    
    data = response.text
    matches = regex.findall(data)
    
    count = 0
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
        
        writer = csv.writer(csvfile, delimiter=';')
        
        for mac, company in matches:
            
            clean_mac = mac.replace('-', '')
            
            clean_company = company.strip()
            
            
            writer.writerow([clean_mac, clean_company])
            count += 1

    print(Back.GREEN + f"DONE! {count} vendor saved into '{OUTPUT_FILE}'.")

if __name__ == "__main__":
    download_and_parse()
