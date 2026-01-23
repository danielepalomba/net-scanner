#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "device_list.h"
#include "logger.h"

#define HASH_MAP_SIZE 1024 

struct DeviceEntry {
    uint8_t mac[6];
    uint8_t ip[4];
    time_t last_seen;
    bool is_trusted;
    struct DeviceEntry *next; 
};

struct DeviceManager {
    struct DeviceEntry *buckets[HASH_MAP_SIZE]; 
    char whitelist_file[256];
    size_t device_count;
};

static unsigned int hash_mac(const uint8_t *mac) {
    unsigned long hash = 5381;
    for (int i = 0; i < 6; i++) {
        hash = ((hash << 5) + hash) + mac[i]; 
    }
    return hash % HASH_MAP_SIZE;
}

static int parse_mac(const char* str, uint8_t* mac_out) {
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", 
        &values[0], &values[1], &values[2], 
        &values[3], &values[4], &values[5]) == 6) {
        for(int i=0; i<6; i++) mac_out[i] = (uint8_t)values[i];
        return 1;
    }
    return 0;
}

DeviceManager* dm_create(const char* whitelist_filename) {
    DeviceManager* dm = malloc(sizeof(DeviceManager));
    if (dm) {
        
        for (int i = 0; i < HASH_MAP_SIZE; i++) {
            dm->buckets[i] = NULL;
        }
        
        dm->device_count = 0;

        if (whitelist_filename) {
            strncpy(dm->whitelist_file, whitelist_filename, sizeof(dm->whitelist_file) - 1);
            dm->whitelist_file[sizeof(dm->whitelist_file) - 1] = '\0';
        } else {
            dm->whitelist_file[0] = '\0';
        }
    }else{
      logger_log(LOG_ERR, "Device Mananger allocation failed");
  }
    return dm;
}

void dm_destroy(DeviceManager* dm) {
    if (!dm){
      logger_log(LOG_WARN, "Trying to deallocate Device Mananger, but Device Mananger is NULL");
      return;
    }
    
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        DeviceEntry *current = dm->buckets[i];
        while (current != NULL) {
            DeviceEntry *next = current->next;
            free(current);
            current = next;
        }
    }
    free(dm);
}

DeviceEntry* dm_lookup(DeviceManager* dm, const uint8_t* mac) {
    if (!dm){
      logger_log(LOG_WARN, "Lookup called while Device Mananger is NULL");
      return NULL;
    }

    unsigned int index = hash_mac(mac);

    DeviceEntry* current = dm->buckets[index];
    while (current != NULL) {
        
        if (memcmp(current->mac, mac, 6) == 0) {
            return current; 
        }
        current = current->next;
    }
    
    return NULL; 
}

DeviceEntry* dm_add_device(DeviceManager* dm, const uint8_t* mac, const uint8_t* ip, bool is_trusted) {
    
    DeviceEntry* existing = dm_lookup(dm, mac);
    if (existing) return existing;

    
    DeviceEntry* new_node = malloc(sizeof(DeviceEntry));
    if (!new_node){
      logger_log(LOG_ERR, "Could not allocate memory for another DeviceEntry");
      return NULL;
    }

    memcpy(new_node->mac, mac, 6);
    if (ip) memcpy(new_node->ip, ip, 4);
    else memset(new_node->ip, 0, 4);
    
    new_node->last_seen = time(NULL);
    new_node->is_trusted = is_trusted;

    unsigned int index = hash_mac(mac);

    new_node->next = dm->buckets[index];
    dm->buckets[index] = new_node;
    
    dm->device_count++;
    
    return new_node;
}

void dm_load_whitelist(DeviceManager* dm) {
    if (!dm || strlen(dm->whitelist_file) == 0) return;

    FILE *f = fopen(dm->whitelist_file, "r");
    if (!f) return;

    char line[64];
    uint8_t mac_bin[6];

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0; 
        
        if (parse_mac(line, mac_bin)) {
            dm_add_device(dm, mac_bin, NULL, true);
        }
    }
    fclose(f);
    //printf("[INFO] Whitelist loaded in Hash Map (%zu entry).\n", dm->device_count);
    logger_log(LOG_INFO, "Whitelist loaded in HashMap (%zu entry)", dm->device_count);
}

void dm_add_to_whitelist_file(DeviceManager* dm, const char* mac_str) {
    if (!dm || strlen(dm->whitelist_file) == 0) return;

    FILE *f = fopen(dm->whitelist_file, "a");
    if (f) {
        fprintf(f, "%s\n", mac_str);
        fclose(f);
    }else{
      logger_log(LOG_ERR, "Could not open whitelis file");
    }
}

bool device_is_trusted(DeviceEntry* device) {
    return device ? device->is_trusted : false;
}

void device_update_last_seen(DeviceEntry* device) {
    if (device) device->last_seen = time(NULL);
}

void device_update_ip(DeviceEntry* device, const uint8_t* new_ip) {
    if (device && new_ip) memcpy(device->ip, new_ip, 4);
}

void device_get_mac_str(DeviceEntry* device, char* buffer, size_t size) {
    if (!device || size < 18) return;
    snprintf(buffer, size, "%02x:%02x:%02x:%02x:%02x:%02x",
        device->mac[0], device->mac[1], device->mac[2],
        device->mac[3], device->mac[4], device->mac[5]);
}
