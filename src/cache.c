#include "../include/cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// 全局变量定义
struct CacheList* cache = NULL;

// 辅助函数：创建新的缓存条目
static struct CacheEntry* createEntry(const char* domain, const uint8_t* ip, int ip_len, uint32_t ttl) {
    struct CacheEntry* entry = (struct CacheEntry*)malloc(sizeof(struct CacheEntry));
    if (!entry) {
        return NULL;
    }

    strncpy(entry->domain, domain, MAX_DOMAIN_LENGTH - 1);
    entry->domain[MAX_DOMAIN_LENGTH - 1] = '\0';
    memcpy(entry->ip, ip, ip_len);
    entry->ip_len = ip_len;
    entry->expire_time = time(NULL) + ttl;
    entry->is_valid = 1;
    entry->next = NULL;
    entry->prev = NULL;

    return entry;
}

// 将节点移动到链表头部
void moveToFront(struct CacheEntry* entry) {
    if (!entry || !cache || entry == cache->head) {
        return;
    }

    // 从当前位置移除
    if (entry->prev) {
        entry->prev->next = entry->next;
    }
    if (entry->next) {
        entry->next->prev = entry->prev;
    }
    if (entry == cache->tail) {
        cache->tail = entry->prev;
    }

    // 移动到头部
    entry->next = cache->head;
    entry->prev = NULL;
    if (cache->head) {
        cache->head->prev = entry;
    }
    cache->head = entry;
    if (!cache->tail) {
        cache->tail = entry;
    }
}

// 从链表中移除节点
void removeEntry(struct CacheEntry* entry) {
    if (!entry || !cache) {
        return;
    }

    if (entry->prev) {
        entry->prev->next = entry->next;
    }
    if (entry->next) {
        entry->next->prev = entry->prev;
    }
    if (entry == cache->head) {
        cache->head = entry->next;
    }
    if (entry == cache->tail) {
        cache->tail = entry->prev;
    }

    free(entry);
    cache->size--;
}

// 缓存相关函数实现
void initCache(int size) {
    cache = (struct CacheList*)malloc(sizeof(struct CacheList));
    if (!cache) {
        printf("Failed to allocate memory for cache\n");
        exit(1);
    }

    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;
    cache->capacity = size;
}

void cleanupCache() {
    if (!cache) {
        return;
    }

    struct CacheEntry* current = cache->head;
    while (current) {
        struct CacheEntry* next = current->next;
        free(current);
        current = next;
    }

    free(cache);
    cache = NULL;
}

int updateCache(const char* domain, const uint8_t* ip, int ip_len, uint32_t ttl) {
    if (!domain || !ip || ip_len <= 0 || ip_len > MAX_IP_LENGTH || !cache) {
        return -1;
    }

    // 查找是否已存在该域名
    struct CacheEntry* current = cache->head;
    while (current) {
        if (current->is_valid && strcmp(current->domain, domain) == 0) {
            // 更新现有条目
            memcpy(current->ip, ip, ip_len);
            current->ip_len = ip_len;
            current->expire_time = time(NULL) + ttl;
            moveToFront(current);
            return 1;
        }
        current = current->next;
    }

    // 创建新条目
    struct CacheEntry* new_entry = createEntry(domain, ip, ip_len, ttl);
    if (!new_entry) {
        return -1;
    }

    // 如果缓存已满，移除最久未使用的条目
    if (cache->size >= cache->capacity) {
        removeEntry(cache->tail);
    }

    // 将新条目添加到头部
    new_entry->next = cache->head;
    if (cache->head) {
        cache->head->prev = new_entry;
    }
    cache->head = new_entry;
    if (!cache->tail) {
        cache->tail = new_entry;
    }
    cache->size++;

    return 1;
}

int findInCache(const char* domain, uint8_t** ip, int* ip_len) {
    if (!domain || !ip || !ip_len || !cache) {
        return 0;
    }

    time_t current_time = time(NULL);
    struct CacheEntry* current = cache->head;

    while (current) {
        if (current->is_valid && strcmp(current->domain, domain) == 0) {
            // 检查是否过期
            if (current_time >= current->expire_time) {
                removeEntry(current);
                return 0;
            }

            // 分配内存并复制IP地址
            *ip = (uint8_t*)malloc(current->ip_len);
            if (!*ip) {
                return 0;
            }
            memcpy(*ip, current->ip, current->ip_len);
            *ip_len = current->ip_len;

            // 将访问的条目移动到头部
            moveToFront(current);
            return 1;
        }
        current = current->next;
    }

    return 0;
}

void printCache() {
    if (!cache) {
        printf("Cache is not initialized\n");
        return;
    }

    printf("Cache contents:\n");
    struct CacheEntry* current = cache->head;
    int index = 0;

    while (current) {
        if (current->is_valid) {
            char ip_str[INET6_ADDRSTRLEN] = {0};
            DWORD ip_str_len = sizeof(ip_str);
            
            if (current->ip_len == 4) {
                // IPv4
                struct sockaddr_in addr = {0};
                addr.sin_family = AF_INET;
                memcpy(&addr.sin_addr, current->ip, 4);
                
                if (WSAAddressToStringA((LPSOCKADDR)&addr, sizeof(addr), NULL, ip_str, &ip_str_len) != 0) {
                    printf("Entry %d: Domain=%s, IP=<conversion error>, Expires=%ld\n", 
                           index, current->domain, current->expire_time);
                    index++;
                    current = current->next;
                    continue;
                }
            } else {
                // IPv6
                struct sockaddr_in6 addr = {0};
                addr.sin6_family = AF_INET6;
                memcpy(&addr.sin6_addr, current->ip, 16);
                
                if (WSAAddressToStringA((LPSOCKADDR)&addr, sizeof(addr), NULL, ip_str, &ip_str_len) != 0) {
                    printf("Entry %d: Domain=%s, IP=<conversion error>, Expires=%ld\n", 
                           index, current->domain, current->expire_time);
                    index++;
                    current = current->next;
                    continue;
                }
            }
            
            printf("Entry %d: Domain=%s, IP=%s, Expires=%ld\n", 
                   index, current->domain, ip_str, current->expire_time);
        }
        index++;
        current = current->next;
    }
}
