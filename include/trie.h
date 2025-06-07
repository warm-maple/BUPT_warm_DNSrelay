#ifndef TRIE_H
#define TRIE_H

#include <stdint.h>

#define MAX_DOMAIN_LENGTH 256
#define MAX_CHILDREN 64  // 0-9, a-z, A-Z, '-', '.', 其他字符

// IP地址类型（只支持IPv4）
#define IPV4_TYPE 4

struct TrieNode {
    struct TrieNode* children[MAX_CHILDREN];
    uint8_t ip[4];      // 只存储IPv4地址
    int is_end;         // 是否是域名结尾
};

// 创建新的Trie节点
struct TrieNode* createTrieNode();

// 插入域名和IPv4地址到Trie树
void insertTrie(struct TrieNode* root, const char* domain, const uint8_t* ip);

// 从Trie树中查找域名对应的IPv4地址
int getIPFromTrie(struct TrieNode* root, const char* domain, uint8_t** ip, int* ip_len);

// 释放Trie树
void freeTrie(struct TrieNode* root);

#endif
