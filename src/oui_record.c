#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "logger.h"
#include "oui_record.h"

static OUI_record oui_db[MAX_OUI_ENTRIES];
static int oui_count = 0;

/*
 * Helper function, it helps to clean the mac taken as parameter. Isolate the first 6 digits and converts with toUpper. 
 */
static void extract_prefix(const char *mac_str, char *prefix_out){
  int j = 0;
  for(int i = 0; mac_str[i] != '\0' && j < 6; i++){
    if(isalnum(mac_str[i])){
      prefix_out[j++] = toupper(mac_str[i]);
    }
  }
  prefix_out[j] = '\0';
}

/*
 *  Compare function for qsort
 */
static int compare_oui_records(const void *a, const void *b) {
    const OUI_record *ra = (const OUI_record *)a;
    const OUI_record *rb = (const OUI_record *)b;
    return strcmp(ra->prefix, rb->prefix);
}

/*
 *  Read the oui data from the file and insert all the value into oui_db struct.
 */
int oui_record_load_db(const char *filename){
  FILE *fd = fopen(filename, "r");
  
  if(!fd){
    logger_log(LOG_ERR, "Could not open OUI file");
    return 0;
  }

  char line[256];
  oui_count = 0;

  while(fgets(line, sizeof(line), fd) && oui_count < MAX_OUI_ENTRIES){
    line[strcspn(line,"\r\n")] = 0; //remove new line
    
    char *token = strtok(line, ";");
    if(token != NULL){
      strncpy(oui_db[oui_count].prefix, token, 6);
      oui_db[oui_count].prefix[6] = '\0';

      token = strtok(NULL, ";");
      if(token != NULL){
        strncpy(oui_db[oui_count].vendor, token, MAX_VENDOR_LEN - 1);
        oui_db[oui_count].vendor[MAX_VENDOR_LEN-1] = '\0';
        oui_count++;
      }
    }
  }
  
  fclose(fd);
  
  // Sort the database for binary search
  qsort(oui_db, oui_count, sizeof(OUI_record), compare_oui_records);
  
  logger_log(LOG_INFO,"Vendors names loaded and sorted (%d entries)", oui_count);
  return 1;
}

/*
 *  Find a vendor into db using binary search.
 */
const char* oui_record_get_vendor_by_mac(const char *mac_str){
  char search_prefix[7];
  extract_prefix(mac_str, search_prefix);

  int left = 0;
  int right = oui_count - 1;

  while (left <= right) {
      int mid = left + (right - left) / 2;
      int cmp = strcmp(search_prefix, oui_db[mid].prefix);

      if (cmp == 0) {
          return oui_db[mid].vendor;
      } else if (cmp < 0) {
          right = mid - 1;
      } else {
          left = mid + 1;
      }
  }

  return "Unknown";
}
