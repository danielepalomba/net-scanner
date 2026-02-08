#include "network_scanner.h"
#include "logger.h"
#include "tcolor.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 256
#define ARP_SCAN_CMD_SIZE 512

/**
 * Parse a MAC address from a string.
 * Expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
 */
static int parse_mac_from_line(const char *line, uint8_t *mac_out) {
  int values[6];

  // Try colon-separated format
  if (sscanf(line, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
             &values[3], &values[4], &values[5]) == 6) {
    for (int i = 0; i < 6; i++) {
      mac_out[i] = (uint8_t)values[i];
    }
    return 1;
  }

  // Try dash-separated format
  if (sscanf(line, "%x-%x-%x-%x-%x-%x", &values[0], &values[1], &values[2],
             &values[3], &values[4], &values[5]) == 6) {
    for (int i = 0; i < 6; i++) {
      mac_out[i] = (uint8_t)values[i];
    }
    return 1;
  }

  return 0;
}

/**
 * Extract MAC address from arp-scan output line.
 * arp-scan output format: "IP_ADDRESS\tMAC_ADDRESS\tVENDOR"
 */
static int extract_mac_from_arpscan_line(const char *line, uint8_t *mac_out,
                                         char *mac_str_out) {
  // Skip empty lines and header/footer lines
  if (strlen(line) < 10 || strstr(line, "Interface:") ||
      strstr(line, "Starting arp-scan") || strstr(line, "packets received")) {
    return 0;
  }

  // Find the first tab (separates IP from MAC)
  const char *first_tab = strchr(line, '\t');
  if (!first_tab) {
    return 0;
  }

  // Skip the tab and any whitespace
  const char *mac_start = first_tab + 1;
  while (*mac_start && isspace(*mac_start)) {
    mac_start++;
  }

  // Extract MAC address string (up to next tab or whitespace)
  char mac_buffer[32];
  int i = 0;
  while (*mac_start && !isspace(*mac_start) && i < 31) {
    mac_buffer[i++] = *mac_start++;
  }
  mac_buffer[i] = '\0';

  // Parse the MAC address
  if (parse_mac_from_line(mac_buffer, mac_out)) {
    if (mac_str_out) {
      strncpy(mac_str_out, mac_buffer, 18);
    }
    return 1;
  }

  return 0;
}

int ns_scan_network(const char *interface, DeviceManager *dm) {
  if (!interface || !dm) {
    logger_log(LOG_ERR, "Invalid parameters for network scan");
    return -1;
  }

  // Build arp-scan command
  char cmd[ARP_SCAN_CMD_SIZE];
  snprintf(cmd, sizeof(cmd), "arp-scan --localnet --interface=%s 2>&1",
           interface);

  logger_log(LOG_INFO, "Starting active network scan on %s...", interface);
  printf(CYAN "\n[SCAN] " RESET "Performing active network scan on %s...\n",
         interface);
  printf(CYAN "[SCAN] " RESET "This may take a few seconds...\n\n");

  // Execute arp-scan
  FILE *fp = popen(cmd, "r");
  if (!fp) {
    logger_log(LOG_ERR, "Failed to execute arp-scan command");
    printf(RED "[ERROR] " RESET
               "Failed to execute arp-scan. Make sure it's installed.\n");
    return -1;
  }

  char line[MAX_LINE_LENGTH];
  int device_count = 0;
  uint8_t mac_bin[6];
  char mac_str[18];

  // Parse output line by line
  while (fgets(line, sizeof(line), fp)) {
    // Remove newline
    line[strcspn(line, "\r\n")] = '\0';

    // Try to extract MAC address from this line
    if (extract_mac_from_arpscan_line(line, mac_bin, mac_str)) {
      // Check if device already exists
      DeviceEntry *existing = dm_lookup(dm, mac_bin);
      if (!existing) {
        // Add to device manager as trusted
        dm_add_device(dm, mac_bin, NULL, true);

        // Add to whitelist file
        dm_add_to_whitelist_file(dm, mac_str);

        printf(GREEN "[FOUND] " RESET "Device: %s\n", mac_str);
        logger_log(LOG_INFO, "Discovered device: %s", mac_str);

        device_count++;
      }
    }
  }

  int status = pclose(fp);

  if (status != 0) {
    logger_log(LOG_WARN, "arp-scan exited with status %d", status);
    printf(RED "[WARN] " RESET
               "arp-scan completed with warnings (status: %d)\n",
           status);
  }

  printf("\n" CYAN "[SCAN] " RESET "Active scan complete. Found " GREEN
         "%d" RESET " new device(s).\n\n",
         device_count);
  logger_log(LOG_INFO, "Active scan complete. Discovered %d new devices",
             device_count);

  return device_count;
}
