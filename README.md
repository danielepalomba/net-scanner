## NET-SCANNER

Designed primarily for Linux OS.

##### How to run

```[bash]
make
```

```[bash]
sudo ./app <network_interface> [--learn]
```

You can easily get the name of your network interface by running the command:

```[bash]
ip a
```

Typically, eth0 for Ethernet or wlo1 for WiFi network interfaces.

---

The program supports two different modes: *Standard* or *AI-driven*. In standard mode, after a learning phase that generates a whitelist of allowed devices, the program performs simple intrusion monitoring. In AI-driven mode, the program is capable of detecting: *ARP Flooding (Denial of Service), ARP Spoofing (Man-in-the-middle), and network scans with nmap*...but we're still working on this :)

---
