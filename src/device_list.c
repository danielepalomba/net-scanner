#include "device_list.h"

DeviceNode *device_list_head = NULL;

void add_device(unsigned char *mac, unsigned char *ip_bytes, int is_trusted){
  DeviceNode *new = (DeviceNode*)malloc(sizeof(DeviceNode));
  
  if(new == NULL){
    fprintf(stderr, "Could not allocate memory for a new DeviceNode\n");
    exit(1);
  }

  memcpy(new->mac,mac,6);
  sprintf(new->ip, "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

  new->last_seen = time(NULL);
  new->is_trusted = is_trusted;
  new->next = device_list_head;
  device_list_head = new;

  //printf("Added to list -> ip: %s - mac (last digit) :%02x\n", new->ip, new->mac[5]); 
}

DeviceNode* find_device(unsigned char *mac){
  DeviceNode *curr = device_list_head;

  while(curr != NULL){
    if(memcmp(curr->mac, mac, 6)==0){
      return curr;
    }
    curr = curr->next;
  }
  return NULL;
}

void load_whitelist() {
    FILE *f = fopen(WHITELIST_FILE, "r");
    if (!f) {
        printf("\033[1;31m[!] Error: File %s not found.\033[0m\n", WHITELIST_FILE);
        return;
    }

    char line[64];
    u_char mac_bytes[6];
    u_char dummy_ip[4] = {0,0,0,0};
    int count = 0;

    printf("\n\033[1;36m       TRUSTED MAC ADDRESSES\033[0m\n");
    printf("==========================================================================\n");

    while (fgets(line, sizeof(line), f)) {
        int values[6];
        
        if (sscanf(line, "%x:%x:%x:%x:%x:%x", 
            &values[0], &values[1], &values[2], 
            &values[3], &values[4], &values[5]) == 6) {
            
            for(int i=0; i<6; i++) mac_bytes[i] = (u_char)values[i];

            add_device(mac_bytes, dummy_ip, 1);
            count++;

            printf("  \033[1;32m•\033[0m  %02x:%02x:%02x:%02x:%02x:%02x\n",
                   mac_bytes[0], mac_bytes[1], mac_bytes[2], 
                   mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        }
    }
    
    printf("==========================================================================\n");
    printf(" Tot in whitelist: %d\n\n", count);

    fclose(f);
}

void save_to_whitelist(const char *mac_str) {
    FILE *f = fopen(WHITELIST_FILE, "a");
    if (f) {
        fprintf(f, "%s\n", mac_str);
        fclose(f);
        printf("[LEARN] Saved: %s\n", mac_str);
    }
}
