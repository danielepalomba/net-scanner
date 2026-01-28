#include "packet_queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Initializes the packet queue as a Ring Buffer.
 * Allocates the fixed-size buffer array.
 */
void queue_init(PacketQueue *q, int max_size) {
  q->buffer = (ArpPacketData *)malloc(sizeof(ArpPacketData) * max_size);
  if (!q->buffer) {
    // Handle allocation failure if necessary, though strict error handling
    // isn't specified, we might print to stderr.
    fprintf(stderr,
            "Fatal: Could not allocate memory for PacketQueue buffer\n");
    exit(1);
  }

  q->head = 0;
  q->tail = 0;
  q->count = 0;
  q->max_size = max_size;
  q->finished = 0;
  pthread_mutex_init(&q->mutex, NULL);
  pthread_cond_init(&q->cond, NULL);
}

/**
 * Thread-safe producer operation: adds a packet to the Ring Buffer.
 * If the queue is full (count == max_size), the packet is DROPPED.
 */
int queue_push(PacketQueue *q, const uint8_t *mac, const uint8_t *ip) {
  pthread_mutex_lock(&q->mutex);

  if (q->count >= q->max_size) {
    // Drop packet policy as requested
    pthread_mutex_unlock(&q->mutex);
    return 0;
  }

  // Write to buffer at tail index
  memcpy(q->buffer[q->tail].src_mac, mac, 6);
  memcpy(q->buffer[q->tail].src_ip, ip, 4);

  // Update tail (Circular)
  q->tail = (q->tail + 1) % q->max_size;
  q->count++;

  // Consumer wake up
  pthread_cond_signal(&q->cond);
  pthread_mutex_unlock(&q->mutex);
  return 1;
}

/**
 * Thread-safe consumer operation: reads a packet from the Ring Buffer.
 */
int queue_pop(PacketQueue *q, ArpPacketData *out_data) {
  pthread_mutex_lock(&q->mutex);

  while (q->count == 0 && !q->finished) {
    pthread_cond_wait(&q->cond, &q->mutex);
  }

  if (q->finished && q->count == 0) {
    pthread_mutex_unlock(&q->mutex);
    return 0; // Stop thread
  }

  // Read from buffer at head index
  *out_data = q->buffer[q->head];

  // Update head (Circular)
  q->head = (q->head + 1) % q->max_size;
  q->count--;

  pthread_mutex_unlock(&q->mutex);
  return 1;
}

/**
 * Gracefully signals the end of operations to all threads.
 */
void queue_signal_finish(PacketQueue *q) {
  pthread_mutex_lock(&q->mutex);
  q->finished = 1;
  pthread_cond_broadcast(&q->cond);
  pthread_mutex_unlock(&q->mutex);
}

/**
 * Teardown routine: cleans up all allocated resources.
 * Frees the main buffer array.
 */
void queue_destroy(PacketQueue *q) {
  pthread_mutex_lock(&q->mutex);

  if (q->buffer) {
    free(q->buffer);
    q->buffer = NULL;
  }

  pthread_mutex_unlock(&q->mutex);
  pthread_mutex_destroy(&q->mutex);
  pthread_cond_destroy(&q->cond);
}
