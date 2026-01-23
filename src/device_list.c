#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "device_list.h"

struct DeviceEntry {
    uint8_t mac[6];
    uint8_t ip[4];
    time_t last_seen;
    bool is_trusted;
    struct DeviceEntry *next;
};

struct DeviceManager {
    struct DeviceEntry *head;
    char whitelist_file[256];
};

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
        dm->head = NULL;
        if (whitelist_filename) {
            strncpy(dm->whitelist_file, whitelist_filename, sizeof(dm->whitelist_file) - 1);
        } else {
            dm->whitelist_file[0] = '\0';
        }
    }
    return dm;
}

void dm_destroy(DeviceManager* dm) {
    if (!dm) return;
    DeviceEntry *current = dm->head;
    while (current != NULL) {
        DeviceEntry *next = current->next;
        free(current);
        current = next;
    }
    free(dm);
}

DeviceEntry* dm_lookup(DeviceManager* dm, const uint8_t* mac) {
    DeviceEntry* current = dm->head;
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
    if (!new_node) return NULL;

    memcpy(new_node->mac, mac, 6);
    if (ip) memcpy(new_node->ip, ip, 4);
    else memset(new_node->ip, 0, 4);
    
    new_node->last_seen = time(NULL);
    new_node->is_trusted = is_trusted;
    
    new_node->next = dm->head;
    dm->head = new_node;
    
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
    printf("[INFO] Whitelist loaded.\n");
}

void dm_add_to_whitelist_file(DeviceManager* dm, const char* mac_str) {
    if (!dm || strlen(dm->whitelist_file) == 0) return;

    FILE *f = fopen(dm->whitelist_file, "a");
    if (f) {
        fprintf(f, "%s\n", mac_str);
        fclose(f);
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
