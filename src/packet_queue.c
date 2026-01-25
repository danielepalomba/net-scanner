#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packet_queue.h"

/**
 * Initializes the packet queue structure and synchronization primitives.
 * Sets the maximum capacity to prevent unbounded memory growth and
 * prepares the mutex and condition variable for thread-safe access.
 */
void queue_init(PacketQueue *q, int max_size) {
    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
    q->max_size = max_size;
    q->finished = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

/**
 * Thread-safe producer operation: adds a packet to the tail of the queue.
 * If the queue is full (capacity reached), the packet is dropped immediately 
 * to avoid blocking the capture thread. Wakes up a waiting consumer on success.
 */
int queue_push(PacketQueue *q, const uint8_t *mac, const uint8_t *ip) {
    pthread_mutex_lock(&q->mutex);

    if (q->count >= q->max_size) {
        pthread_mutex_unlock(&q->mutex);
        return 0; // Packet dropped
    }

    QueueNode *node = malloc(sizeof(QueueNode));
    if (!node) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }

    memcpy(node->data.src_mac, mac, 6);
    memcpy(node->data.src_ip, ip, 4);
    node->next = NULL;

    if (q->tail) {
        q->tail->next = node;
    } else {
        q->head = node;
    }
    q->tail = node;
    q->count++;

    // Consumer wake up
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

/**
 * Thread-safe consumer operation: removes and returns a packet from the head.
 * Blocks execution if the queue is empty until new data arrives or the 
 * finish signal is received. Returns 0 only when the queue is stopped and empty.
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

    QueueNode *node = q->head;
    *out_data = node->data; 

    q->head = node->next;
    if (q->head == NULL) {
        q->tail = NULL;
    }
    q->count--;

    free(node);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

/**
 * Gracefully signals the end of operations to all threads.
 * Sets the finished flag and broadcasts to all blocking consumers 
 * to break their wait loops, allowing them to exit safely.
 */
void queue_signal_finish(PacketQueue *q) {
    pthread_mutex_lock(&q->mutex);
    q->finished = 1;
    pthread_cond_broadcast(&q->cond); 
    pthread_mutex_unlock(&q->mutex);
}

/**
 * Teardown routine: cleans up all allocated resources.
 * Iterates through the list to free remaining nodes and destroys 
 * the mutex and condition variable to prevent memory leaks.
 */
void queue_destroy(PacketQueue *q) {
    pthread_mutex_lock(&q->mutex);
    QueueNode *current = q->head;
    while (current) {
        QueueNode *next = current->next;
        free(current);
        current = next;
    }
    pthread_mutex_unlock(&q->mutex);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}
