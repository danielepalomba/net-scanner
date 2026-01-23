#ifndef DEVICE_LIST_H
#define DEVICE_LIST_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WHITELIST_FILE "whitelist.txt"


typedef struct DeviceNode {
    unsigned char mac[6];    
    char ip[16];             
    time_t last_seen;        
    int is_trusted;
    struct DeviceNode *next; 
} DeviceNode;

extern DeviceNode *device_list_head;

DeviceNode* find_device(unsigned char *mac);
void add_device(unsigned char *mac, unsigned char *ip_bytes, int is_trusted);

void save_to_whitelist(const char *mac_str);
void load_whitelist();

#endif
