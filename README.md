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

On first launch, you should run the program in **learning mode**. This mode generates a *MAC address whitelist*. 

After that, you have two options:

- *Standard mode:* The scanner will perform a simple comparison between the MAC addresses received in the ARP packets and those present in the list, detecting any anomalies. No attacks other than simple anomalous MAC addresses will be detected!

- *AI-Driven*: Once you've collected enough data and trained a sufficiently performant model on your network traffic, you can run the ai-engine.py script and then start the sniffer in AI mode. If the model has been trained well, it will be able to detect not only unknown MAC addresses, but also ARP Spoofing, massive scans with the *nmap* command, and MITM attacks.

#### How to train the model?

1. First of all you need to **generate a MAC address whitelist**. It is important that the model is trained only with trusted devices, otherwise it will think that ARP traffic from untrusted devices is normal. To do this, start the sniffer in learning mode and wait for all MAC addresses to be detected, you can also manually enter them into the whitelist if necessary.
2. Once the list is generated, you're ready to start **collecting data on your network traffic**. To do so, run the collector.py script and then run the sniffer in AI mode. The longer the collector listens, the better the model generated.
3. Once you have the data, run the trainer.py script, which will **train the model** and save it to a .pkl file.
4. You are **ready**, start the ai-engine and then the sniffer in ai-mode, any anomalies will be reported to you.

---
*N.B. This is a project created purely for learning purposes; it's not a precise tool, and there may be errors. If you find any, please let me know :)*









