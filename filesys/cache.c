#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/thread.h"
// #include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"

// #define 64 64
// #define CACHE_WRITE_INTV (1 * TIMER_FREQ)


// static struct list ahead_queue;
// static struct lock ahead_lock;
// static struct condition ahead_cond;

// struct ahead_entry {
//     block_sector_t sector;
//     struct list_elem elem;
// };

struct cache_entry {
    uint8_t buffer[BLOCK_SECTOR_SIZE];
    struct lock cache_entry_lock;
    bool dirty;
    int valid;
    // bool accessed;
    block_sector_t sector_number;
};

static struct cache_entry cache[64];

static struct lock cache_lock;

static struct cache_entry *cache_find(block_sector_t sector);
static struct cache_entry *cache_evict(void);
// static void cache_write_behind(void *aux UNUSED);
// static void cache_read_ahead(void *aux UNUSED);

void cache_init(void) {
    int i = 0;
    struct cache_entry *a = cache[i];
    while (i < 64){
      a = &cache[i];
      lock_init(&a->cache_entry_lock);
      a->dirty = false;
      a->valid = 0;
      i = i + 1;
    }
    lock_init(&cache_lock);
    // list_init(&ahead_queue);
    // lock_init(&ahead_lock);
    // cond_init(&ahead_cond);
    // thread_create("write_behind", PRI_DEFAULT, cache_write_behind, NULL);
    // thread_create("read_ahead", PRI_DEFAULT, cache_read_ahead, NULL);
}

void cache_flush_all(void) {
    size_t i;
    for (i = 0; i < 64; ++ i) {
        struct cache_entry *ce = cache + i;
        lock_acquire(&ce->cache_entry_lock);
        if (ce->valid && ce->dirty) {
            block_write(fs_device, ce->sector_number, ce->buffer);
            ce->dirty = false;
        }
        lock_release(&ce->cache_entry_lock);
    }
}

static struct cache_entry *cache_find(block_sector_t sector) {
    size_t i;
    for (i = 0; i < 64; ++ i) {
        struct cache_entry *ce = cache + i;
        lock_acquire(&ce->cache_entry_lock);
        if (ce->valid && ce->sector_number == sector) {
            return ce;
        }
        lock_release(&ce->cache_entry_lock);
    }
    return NULL;
}

void cache_read(block_sector_t sector, void *buffer) {
    cache_read_at(sector, buffer, BLOCK_SECTOR_SIZE, 0);
}

void cache_read_at(block_sector_t sector, void *buffer,off_t size, off_t offset) {
    lock_acquire(&cache_lock);
    struct cache_entry *ce = cache_find(sector);
    if (!ce) {
        // miss!
        ce = cache_evict();
        lock_release(&cache_lock);
        ASSERT(ce);
        ce->sector_number = sector;
        ce->dirty = false;
        block_read(fs_device, sector, ce->buffer);
    } else {
        lock_release(&cache_lock);
    }
    if (buffer) {
        memcpy(buffer, ce->buffer + offset, (size_t) size);
    }
    // ce->accessed = true;
    lock_release(&ce->cache_entry_lock);
}

static struct cache_entry *cache_evict(void) {
    size_t hand = 0;
    while (true) {
        struct cache_entry *ce = cache + hand;
        bool succ = lock_try_acquire(&ce->cache_entry_lock);
        if (!succ) {
            hand = (hand + 1) % 64;
            continue;
        }
        if (!ce->valid) {
            ce->valid = 1;
            return ce;
        }
        // if (ce->accessed) {
        //     ce->accessed = false;
        // }
        else {
            // evict him! lol
            if (ce->dirty) {
                block_write(fs_device, ce->sector_number, ce->buffer);
                ce->dirty = false;
            }
            return ce;
        }
        lock_release(&ce->cache_entry_lock);
        hand = (hand + 1) % 64;
    }
    NOT_REACHED();
}

void cache_write(block_sector_t sector, const void *buffer) {
    cache_write_at(sector, buffer, BLOCK_SECTOR_SIZE, 0);
}

void cache_write_at(block_sector_t sector, const void *buffer,off_t size, off_t offset) {
    ASSERT(buffer);
    lock_acquire(&cache_lock);
    struct cache_entry *ce = cache_find(sector);
    if (!ce) {
        // miss!
        ce = cache_evict();
        lock_release(&cache_lock);
        ASSERT(ce);
        ce->sector_number = sector;
        ce->dirty = false;
        if (size != BLOCK_SECTOR_SIZE)
            block_read(fs_device, sector, ce->buffer);
    } else {
        lock_release(&cache_lock);
    }
    memcpy(ce->buffer + offset, buffer, (size_t) size);
    // ce->accessed = true;
    ce->dirty = true;
    lock_release(&ce->cache_entry_lock);
}

// static void cache_write_behind(void *aux UNUSED) {
//     while (true) {
//         timer_sleep(CACHE_WRITE_INTV);
//         cache_flush_all();
//     }
//     NOT_REACHED();
// }

// static void cache_read_ahead(void *aux UNUSED) {
//     while (true) {
//         lock_acquire(&ahead_lock);
//         while (list_empty(&ahead_queue))
//             cond_wait(&ahead_cond, &ahead_lock);
//         struct ahead_entry *ae = list_entry(list_pop_front(&ahead_queue),
//                 struct ahead_entry, elem);
//         lock_release(&ahead_lock);
//         block_sector_t sector = ae->sector;
//         free(ae);
//         cache_read(sector, NULL);
//     }
//     NOT_REACHED();
// }
//
// void cache_read_ahead_put(block_sector_t sector) {
//     lock_acquire(&ahead_lock);
//     struct ahead_entry *ae = malloc(sizeof(struct ahead_entry));
//     ae->sector = sector;
//     list_push_back(&ahead_queue, &ae->elem);
//     cond_signal(&ahead_cond, &ahead_lock);
//     lock_release(&ahead_lock);
// }
