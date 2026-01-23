#ifndef DEVICE_LIST_H
#define DEVICE_LIST_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

typedef struct DeviceManager DeviceManager;
typedef struct DeviceEntry DeviceEntry;

DeviceManager* dm_create(const char* whitelist_filename);
void dm_destroy(DeviceManager* dm);

DeviceEntry* dm_lookup(DeviceManager* dm, const uint8_t* mac);
DeviceEntry* dm_add_device(DeviceManager* dm, const uint8_t* mac, const uint8_t* ip, bool is_trusted);

void dm_load_whitelist(DeviceManager* dm);
void dm_add_to_whitelist_file(DeviceManager* dm, const char* mac_str);

bool device_is_trusted(DeviceEntry* device);
void device_update_last_seen(DeviceEntry* device);
void device_update_ip(DeviceEntry* device, const uint8_t* new_ip);

void device_get_mac_str(DeviceEntry* device, char* buffer, size_t size);

#endif
