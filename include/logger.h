#ifndef LOGGER_H
#define LOGGER_H

typedef enum{
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARN,
  LOG_ERR
}LogLevel;

int logger_init(const char* filename);
void logger_close();
void logger_log(LogLevel level, const char *fmt, ...);

#endif
