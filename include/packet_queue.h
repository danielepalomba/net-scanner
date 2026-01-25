#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <stdint.h>
#include <pthread.h>

typedef struct{
  uint8_t src_mac[6];
  uint8_t src_ip[4];
}ArpPacketData;

typedef struct QueueNode{
  ArpPacketData data;
  struct QueueNode *next;
}QueueNode;

typedef struct{
  QueueNode *head;
  QueueNode *tail;
  int count;
  int max_size;
  int finished;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
}PacketQueue;

void queue_init(PacketQueue *q, int max_size);

int queue_push(PacketQueue *q, const uint8_t *mac, const uint8_t *ip);

int queue_pop(PacketQueue *q, ArpPacketData *out_data);

void queue_destroy(PacketQueue *q);

void queue_signal_finish(PacketQueue *q);

#endif
