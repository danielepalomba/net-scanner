#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#include "device_list.h"
#include "oui_record.h"
#include "tcolor.h"
#include "logger.h"
#include "packet_queue.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 7777

// Globals
int LEARNING_MODE = 0;
int AI_MODE = 0;
DeviceManager* net_manager = NULL;
pcap_t *handle = NULL;
PacketQueue packet_queue;

void signal_handler(int sig) {
    logger_log(LOG_INFO, "Received closing signal (%d)...", sig);
    if (handle) pcap_breakloop(handle);
}

// SYNC HANDLER AI_MODE
void std_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_header = (struct ether_arp *) (packet + sizeof(struct ether_header));
        
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp_header->arp_sha[0], arp_header->arp_sha[1],
                 arp_header->arp_sha[2], arp_header->arp_sha[3],
                 arp_header->arp_sha[4], arp_header->arp_sha[5]);

        const char *vendor_name = oui_record_get_vendor_by_mac(mac_str);
        DeviceEntry *device = dm_lookup(net_manager, arp_header->arp_sha);

        if (device != NULL) { 
            
            device_update_last_seen(device);
            device_update_ip(device, arp_header->arp_spa);

            if (!device_is_trusted(device)) {
                 printf(RED "\n[ALERT REPEAT]" RESET " Unauthorized device is active!\n");
                 printf("MAC: " CYAN "%s" RESET " [%s]\n", mac_str, vendor_name);
                 
                 logger_log(LOG_WARN, "ALERT: Intruso attivo! MAC: %s", mac_str);
            }

        } else { 
            
            if (LEARNING_MODE) {
                
                printf(GREEN "[NEW]" RESET " New device found -> adding to list...\n");
                printf("      MAC: %s (%s)\n", mac_str, vendor_name);

                
                logger_log(LOG_INFO, "New Device (Learning): %s [%s]", mac_str, vendor_name);
                
                dm_add_device(net_manager, arp_header->arp_sha, arp_header->arp_spa, true);
                dm_add_to_whitelist_file(net_manager, mac_str);

            } else {
                
                printf(RED "\n[ALERT]" RESET " Unauthorized device found!\n");
                printf("MAC: " CYAN "%s" RESET " [%s]\n", mac_str, vendor_name);
                printf("IP : %d.%d.%d.%d\n", 
                       arp_header->arp_spa[0], arp_header->arp_spa[1],
                       arp_header->arp_spa[2], arp_header->arp_spa[3]);

                logger_log(LOG_ERR, "ALERT: New Intruder! %s [%s] IP: %d.%d.%d.%d", 
                           mac_str, vendor_name,
                           arp_header->arp_spa[0], arp_header->arp_spa[1],
                           arp_header->arp_spa[2], arp_header->arp_spa[3]);
                
                dm_add_device(net_manager, arp_header->arp_sha, arp_header->arp_spa, false);
            }
        }
    }
}

// ASYNC HANDLER (AI_MODE = 1)
void fast_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_header = (struct ether_arp *) (packet + sizeof(struct ether_header));
        
        queue_push(&packet_queue, arp_header->arp_sha, arp_header->arp_spa);
    }
}

// CONSUMER THREAD
void *consumer_routine(void *arg) {
    ArpPacketData pkt;
    char mac_str[18];
    int sock_fd = -1;
    struct sockaddr_in serv_addr;

    // Socket
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        logger_log(LOG_ERR, "Could not create socket");
    } else {
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(SERVER_PORT);

        if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
            logger_log(LOG_ERR, "Invalid address");
            close(sock_fd);
            sock_fd = -1;
        } else {
            if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
                logger_log(LOG_WARN, "Connection Failed to AI Engine");
                close(sock_fd);
                sock_fd = -1; 
            } else {
                logger_log(LOG_INFO, "Connected to AI Engine");
            }
        }
    }

    while (queue_pop(&packet_queue, &pkt)) {
        
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 pkt.src_mac[0], pkt.src_mac[1], pkt.src_mac[2],
                 pkt.src_mac[3], pkt.src_mac[4], pkt.src_mac[5]);

        const char *vendor_name = oui_record_get_vendor_by_mac(mac_str);
        DeviceEntry *device = dm_lookup(net_manager, pkt.src_mac);

        if (device != NULL) { 
            device_update_last_seen(device);
            device_update_ip(device, pkt.src_ip);
            
            if (!device_is_trusted(device)) {
                 logger_log(LOG_WARN, "Unknown device active! MAC: %s", mac_str);
            }
        } else { 
            if (LEARNING_MODE) {
                logger_log(LOG_INFO, "New Device (Learning): %s [%s]", mac_str, vendor_name);
                dm_add_device(net_manager, pkt.src_mac, pkt.src_ip, true);
                dm_add_to_whitelist_file(net_manager, mac_str);
            } else {
                logger_log(LOG_ERR, "New Intruder! %s [%s]", mac_str, vendor_name);
                dm_add_device(net_manager, pkt.src_mac, pkt.src_ip, false);
            }
        }

        if (sock_fd >= 0) {
            char data_buffer[128];
            // TIMESTAMP,MAC,IP (csv format)
            snprintf(data_buffer, sizeof(data_buffer), "%ld,%s,%d.%d.%d.%d\n", 
                     time(NULL), 
                     mac_str, 
                     pkt.src_ip[0], pkt.src_ip[1], pkt.src_ip[2], pkt.src_ip[3]);
            
            if (send(sock_fd, data_buffer, strlen(data_buffer), 0) < 0) {
                logger_log(LOG_ERR, "Failed to send packet to AI (Disconnecting)");
                close(sock_fd);
                sock_fd = -1; 
            }
        }
    }
    
    if (sock_fd >= 0) close(sock_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    char *device = NULL;
    char errbuf[PCAP_ERRBUF_SIZE]; 
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pthread_t worker_tid; // ID thread worker
    
    if(!logger_init("events.log")){
      fprintf(stderr, "Could not initialize logger file\n");
      return 1;
    } 

    signal(SIGINT, signal_handler);

    if (!oui_record_load_db("oui.csv")) {
      logger_log(LOG_WARN, "Could not load oui.csv file.");
    }

    net_manager = dm_create("whitelist.txt");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--learn") == 0) {
            LEARNING_MODE = 1;
        } 
        else if (strcmp(argv[i], "-ia") == 0) {
            AI_MODE = 1;
        } 
        else {
            if (device == NULL) {
                device = argv[i];
            }
        }
    } 

    logger_log(LOG_INFO, "Starting net-scanner on %s...", device);
    if (AI_MODE) logger_log(LOG_INFO, "Mode: AI/Async (High Performance)");
    else logger_log(LOG_INFO, "Mode: Standard (Synchronous)");


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
    
    if (AI_MODE) {
        printf(CYAN "IA Mode is active, for more info, check .log file\n" RESET);
    
        queue_init(&packet_queue, 1000); 
        
        if (pthread_create(&worker_tid, NULL, consumer_routine, NULL) != 0) {
            logger_log(LOG_ERR, "Failed to create worker thread!");
            return 1;
        }
        
        pcap_loop(handle, -1, fast_packet_handler, NULL);
        
        logger_log(LOG_INFO, "Stopping worker thread...");
        queue_signal_finish(&packet_queue);
        pthread_join(worker_tid, NULL);
        queue_destroy(&packet_queue);
        
    } else {
        pcap_loop(handle, -1, std_packet_handler, NULL);
    }

    pcap_close(handle);
    dm_destroy(net_manager);
    logger_close();
    
    printf("\nScanner stopped correctly.\n");
    return 0;
}
