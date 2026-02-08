#ifndef NETWORK_SCANNER_H
#define NETWORK_SCANNER_H

#include "device_list.h"

/**
 * Performs an active network scan using arp-scan to discover all devices
 */
int ns_scan_network(const char *interface, DeviceManager *dm);

#endif
