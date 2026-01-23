#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #include <pcap.h>
    
    #define ETHERTYPE_ARP 0x0806

    struct ether_header {
        u_char  ether_dhost[6];
        u_char  ether_shost[6];
        u_short ether_type;
    };

    /* Flat structure to match Unix definition access */
    struct ether_arp {
        u_short ar_hrd;
        u_short ar_pro;
        u_char  ar_hln;
        u_char  ar_pln;
        u_short ar_op;
        u_char  arp_sha[6];
        u_char  arp_spa[4];
        u_char  arp_tha[6];
        u_char  arp_tpa[4];
    };
#else
    #include <pcap.h>
    #include <arpa/inet.h>
    #include <net/ethernet.h>
    #include <netinet/if_ether.h>
#endif

#include "device_list.h"
#include "tcolor.h"
#include "oui_record.h"

int LEARNING_MODE = 0;

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


/*
 * It handles raw packets, extracts information from them, and checks whether the device associated with the newly obtained data is present
 * in the list. If it isn't, it adds it.
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    /* cast to ether_header */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    /* check [FRAME_TYPE] -> 0x0806 for ARP pkt */
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        
        /* cast to arp_header [ether_header](14 bytes) [ARP pkt](28 bytes) */  
        struct ether_arp *arp_header;
        arp_header = (struct ether_arp *) (packet + sizeof(struct ether_header));
         
        //Check if the device is alredy present into the list
        DeviceNode *device = find_device(arp_header->arp_sha);
        
        // Stringa MAC per log
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp_header->arp_sha[0], arp_header->arp_sha[1],
                 arp_header->arp_sha[2], arp_header->arp_sha[3],
                 arp_header->arp_sha[4], arp_header->arp_sha[5]);
       
        //vendor name lookup
        const char *vendor_name = oui_record_get_vendor_by_mac(mac_str);
        
        if (device != NULL) { //already in RAM
             
            device->last_seen = time(NULL);

            memcpy(device->ip, arp_header->arp_spa, 4);

            if (!device->is_trusted) { /* Not authorized but already discovered */
              //printf("[ALERT REPEAT] Not authorized device is alredy talking!\n");
            }

        } else { //new device
            
            if (LEARNING_MODE) {
                
                printf(GREEN "[NEW]" RESET " New device founded -> adding to list... %s\n", mac_str);
                printf("      MAC: %s (%s)\n", mac_str, vendor_name);

                add_device(arp_header->arp_sha, arp_header->arp_spa, 1); // 1 = Trusted
                save_to_whitelist(mac_str);
            } else {
                
                printf(RED "\n[ALERT]" RESET " Not authorized device was found!\n");
                printf("MAC: " CYAN "%s" RESET " [%s]\n", mac_str, vendor_name);
                printf("IP : %d.%d.%d.%d\n", 
                       arp_header->arp_spa[0], arp_header->arp_spa[1],
                       arp_header->arp_spa[2], arp_header->arp_spa[3]);
                
                //save into RAM as not authorized
                add_device(arp_header->arp_sha, arp_header->arp_spa, 0); // 0 = Untrusted  
            }
        }
    }
}

/* Works passively */
int main(int argc, char *argv[]) {
    char *device;              // interface name
    char errbuf[PCAP_ERRBUF_SIZE]; // err buff
    pcap_t *handle;            // session sniffing handler 
    struct bpf_program fp;     // compiled filter
    char filter_exp[] = "arp"; // kernel arp filter
    bpf_u_int32 mask;          // subnet mask
    bpf_u_int32 net;           // ip addr
    
    //load vendors name from file
    if(!oui_record_load_db("oui.csv")){
      fprintf(stderr, RED "[WARNING]" RESET " Cannot load oui.csv. Vendor resolution disabled.\n");
    }

    if (argc == 1) {
        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            fprintf(stderr, "Could not find a valid interface: %s\n", errbuf);
            return 2;
        }
    } else if (argc == 2){
        device = argv[1];
        load_whitelist();
    } else if (argc == 3 && strcmp(argv[2], "--learn") == 0){
      LEARNING_MODE = 1;
      printf("Scanner starting in learning mode...\n");
      printf("All new devices will be added to the whitelist\n");
      printf("Press CTRL+c to stop!\n");
      
      device = argv[1];
    }

    printf("Listening to: %s\n", device);

    // obtain ip and mask of the network (needed for filter)
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Could not obtain a netmask %s: %s\n", device, errbuf);
        net = 0;
        mask = 0;
    }

    // open the session
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open the selected interface %s: %s\n", device, errbuf);
        return 2;
    }

    // compile the arp filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse arp filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // apply arp filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install arp filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    
  return 0;
}
