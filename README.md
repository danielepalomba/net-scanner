## NET-SCANNER

Designed primarily for Linux OS.

##### How to run (Standard or Learning mode)

```[bash]
make
```

```[bash]
sudo ./app <network_interface> [--learn]
```

##### How to run (AI-Driven)
```[bash]
    Start first ai-engine.py
```
```[bash]
sudo ./app <network_interface> -ia
```

You can easily get the name of your network interface by running the command:

```[bash]
ip a
```

Typically, eth0 for Ethernet or wlo1 for WiFi network interfaces.

---

On first launch, you have two options to create the *MAC address whitelist*:

1. **Active Scanning (Recommended)**: Run the program with the `--scan` flag to immediately discover all devices on your network:

```bash
sudo ./app <network_interface> --scan
```

This will use `arp-scan` to actively discover all devices on your local network and populate the whitelist immediately.

2. **Learning Mode (Passive)**: Run the program in learning mode to passively build the whitelist as ARP packets are detected:

```bash
sudo ./app <network_interface> --learn
```


**Combining Both Methods:**

You can use both `--scan` and `--learn` together for comprehensive coverage:

```bash
sudo ./app <network_interface> --scan --learn
```

When both flags are used:
1. **First (Active Scan)**: The program immediately performs an active scan using `arp-scan` to discover all devices currently on the network and adds them to the whitelist
2. **Then (Passive Learning)**: The program continues running in learning mode, monitoring ARP traffic. Any NEW devices that appear on the network after the initial scan (devices that weren't found during the scan) will also be automatically added to the whitelist

This combination is useful when:
- You want to quickly populate the whitelist with all existing devices (via `--scan`)
- You also want to automatically add any devices that join the network later while the program is running (via `--learn`)


---

After that, you have two options:

- *Standard mode:* The scanner will perform a simple comparison between the MAC addresses received in the ARP packets and those present in the list, detecting any anomalies. No attacks other than simple anomalous MAC addresses will be detected!

- *AI-Driven*: Once you've collected enough data and trained a sufficiently performant model on your network traffic, you can run the ai-engine.py script and then start the sniffer in AI mode. If the model has been trained well, it will be able to detect not only unknown MAC addresses, but also ARP flooding, massive scans with the *nmap* command, and MITM attacks.

#### How to train the model?

1. First of all you need to **generate a MAC address whitelist**. It is important that the model is trained only with trusted devices, otherwise it will think that ARP traffic from untrusted devices is normal. To do this, start the sniffer in learning mode and wait for all MAC addresses to be detected, you can also manually enter them into the whitelist if necessary.
2. Once the list is generated, you're ready to start **collecting data on your network traffic**. To do so, run the collector.py script and then run the sniffer in AI mode. The longer the collector listens, the better the model generated.
3. Once you have the data, run the trainer.py script, which will **train the model** and save it to a .pkl file.
4. You are **ready**, start the ai-engine and then the sniffer in ai-mode, any anomalies will be reported to you.

---

![GUI_EXAMPLE](img/gui.png)

---
*N.B. This is a project created purely for learning purposes; it's not a precise tool, and there may be errors. If you find any, please let me know :)*









