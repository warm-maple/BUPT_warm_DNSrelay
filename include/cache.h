#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>
#include <winsock2.h>
#include <time.h>

// 缓存常量定义
#define MAX_CACHE_SIZE 1000
#define MAX_DOMAIN_LENGTH 256
#define MAX_IP_LENGTH 16  // 支持IPv6
#define TRUE 1
#define FALSE 0

// 缓存条目结构
struct CacheEntry {
    char domain[MAX_DOMAIN_LENGTH];
    uint8_t ip[MAX_IP_LENGTH];
    int ip_len;
    time_t expire_time;
    int is_valid;
    struct CacheEntry* next;  // 指向下一个节点
    struct CacheEntry* prev;  // 指向前一个节点
};

// 缓存链表结构
struct CacheList {
    struct CacheEntry* head;  // 指向最近使用的节点
    struct CacheEntry* tail;  // 指向最久未使用的节点
    int size;                 // 当前缓存大小
    int capacity;             // 缓存容量
};

// 全局变量声明
extern struct CacheList* cache;

// 缓存相关函数声明
void initCache(int size);
void cleanupCache();
int updateCache(const char* domain, const uint8_t* ip, int ip_len, uint32_t ttl);
int findInCache(const char* domain, uint8_t** ip, int* ip_len);
void printCache();
void moveToFront(struct CacheEntry* entry);  // 将节点移动到链表头部
void removeEntry(struct CacheEntry* entry);  // 从链表中移除节点

#endif // CACHE_H
