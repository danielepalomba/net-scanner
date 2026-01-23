#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include "logger.h"

static FILE *log_fd = NULL;

static const char *level_strings[] = {"DEBUG", "INFO", "WARN", "ERR"};

int logger_init(const char *filename){
  if(filename == NULL){
    log_fd = stdout;
    return 1;
  }

  log_fd = fopen(filename, "a"); //open in mode "a" in order to not delete previous log, this could be good in case of error or crash

  if(log_fd == NULL){
    perror("Could not open log file");
    log_fd = stdout;
    return 0;
  }

  return 1;
}

void logger_close(){
  if(log_fd != NULL && log_fd != stdout){
    fclose(log_fd);
    log_fd = NULL;
  }
}

void logger_log(LogLevel level, const char *fmt, ...){
  if(log_fd == NULL) return;

  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char time_str[20];

  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

  fprintf(log_fd, "[%s] [%-5s] ", time_str, level_strings[level]);

  va_list args;
  va_start(args, fmt);

  vfprintf(log_fd, fmt, args);
  
  va_end(args);

  fprintf(log_fd, "\n");
  fflush(log_fd);
}

