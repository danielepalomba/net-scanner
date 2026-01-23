#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#include "device_list.h"
#include "oui_record.h"
#include "tcolor.h"
#include "logger.h"

int LEARNING_MODE = 0;
DeviceManager* net_manager = NULL;
pcap_t *handle = NULL;

/*
 * ARP PACKET (42 Bytes total)
 *
 * Ethernet Header (14 Bytes)
 * +------------------------+------------------------+-----------+
 * | Destination MAC (6)    | Source MAC (6)         | Type (2)  |
 * +------------------------+------------------------+-----------+
 *
 * ARP Payload (28 Bytes)
 * +-----------+-----------+-----------+-----------+-----------+
 * | Hw Type(2)| Pr Type(2)| Hw Len(1) | Pr Len(1) | Opcode(2) |
 * +-----------+-----------+-----------+-----------+-----------+
 * | Sender MAC (6)        | Sender IP (4)                 |
 * +-----------------------+-----------------------------------+
 * | Target MAC (6)        | Target IP (4)                 |
 * +-----------------------+-----------------------------------+
 */

void signal_handler(int sig) {
    logger_log(LOG_INFO, "Received closing signal (%d)...", sig);
    if (handle) pcap_breakloop(handle);
}

/*
 * It handles raw packets, extracts information from them, and checks whether the device associated with the newly obtained data is present
 * in the list. If it isn't, it adds it.
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_header = (struct ether_arp *) (packet + sizeof(struct ether_header));
        
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp_header->arp_sha[0], arp_header->arp_sha[1],
                 arp_header->arp_sha[2], arp_header->arp_sha[3],
                 arp_header->arp_sha[4], arp_header->arp_sha[5]);

        // OUI Lookup
        const char *vendor_name = oui_record_get_vendor_by_mac(mac_str);

        // Devide Mananger Lookup
        DeviceEntry *device = dm_lookup(net_manager, arp_header->arp_sha);

        if (device != NULL) { //Already in memory device, we only update his status
            
            device_update_last_seen(device);
            device_update_ip(device, arp_header->arp_spa);

            if (!device_is_trusted(device)) {
                 //Unknown device but already discovered
            }

        } else { 
            // New device
            if (LEARNING_MODE) {
                printf(GREEN "[NEW]" RESET " Adding trusted device...\n");
                printf("      MAC: %s (%s)\n", mac_str, vendor_name);
                
                dm_add_device(net_manager, arp_header->arp_sha, arp_header->arp_spa, true);
                dm_add_to_whitelist_file(net_manager, mac_str);

            } else {
                printf(RED "\n[ALERT]" RESET " Unauthorized device found!\n");
                printf("MAC: " CYAN "%s" RESET " [%s]\n", mac_str, vendor_name);
                printf("IP : %d.%d.%d.%d\n", 
                       arp_header->arp_spa[0], arp_header->arp_spa[1],
                       arp_header->arp_spa[2], arp_header->arp_spa[3]);
                
                // Add as untrusted device
                dm_add_device(net_manager, arp_header->arp_sha, arp_header->arp_spa, false);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    char *device = NULL;
    char errbuf[PCAP_ERRBUF_SIZE]; 
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if(!logger_init("events.log")){
      fprintf(stderr, "Could not initialize logger file\n");
      return 1;
    } 

    signal(SIGINT, signal_handler);


    if (!oui_record_load_db("oui.csv")) {
      logger_log(LOG_WARN, "Could not load oui.csv file.");
    }

    net_manager = dm_create("whitelist.txt");

    if (argc == 1) {
        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            logger_log(LOG_ERR, "No interface founded: %s", errbuf);
            return 2;
        }
        dm_load_whitelist(net_manager); 
    } else if (argc >= 2) {
        device = argv[1];
        dm_load_whitelist(net_manager);
        
        if (argc == 3 && strcmp(argv[2], "--learn") == 0) {
            LEARNING_MODE = 1;
            logger_log(LOG_INFO, "Learning mode is active | Press Ctrl+c to exit.");
        }
    }

    logger_log(LOG_INFO, "Starting net-scanner...");

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        net = 0; mask = 0;
    }

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        logger_log(LOG_ERR, "Could not open device %s : %s", device, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       logger_log(LOG_ERR, "Filter error: %s", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
       logger_log(LOG_ERR, "Could not install filter: %s", pcap_geterr(handle));
        return 2;
    }

    printf(CYAN "Sniffing ARP packets...\n" RESET);  
    
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    dm_destroy(net_manager);
    logger_close();
    
    return 0;
}
