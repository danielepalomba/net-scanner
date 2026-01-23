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

On first launch, you should run the program in **learning mode**. This mode generates a *MAC address whitelist*. After that, you can simply run the program in standard mode, and all devices not on the whitelist will be displayed. Specifically, the MAC address, vendor, and IP address will be displayed.

---

Works in progress...
