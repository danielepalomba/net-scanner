#ifndef OUI_RECORD
#define OUI_RECORD

#define MAX_OUI_ENTRIES 40000
#define MAX_VENDOR_LEN 64

typedef struct {
  char prefix[7]; //first 6 + terminator
  char vendor[MAX_VENDOR_LEN];
}OUI_record;

int oui_record_load_db(const char *filename);

const char* oui_record_get_vendor_by_mac(const char *mac_str);

#endif
