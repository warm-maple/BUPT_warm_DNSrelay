#include "../include/trie.h"
#include "../include/cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// 字符映射表
static int char_map[256] = {0};  // 初始化为0

// 初始化字符映射表
static void initCharMap() {
    for (int i = 0; i < 256; i++) {
        if (isdigit(i)) {
            char_map[i] = i - '0';  // 0-9: 0-9
        } else if (islower(i)) {
            char_map[i] = i - 'a' + 10;  // a-z: 10-35
        } else if (isupper(i)) {
            char_map[i] = i - 'A' + 36;  // A-Z: 36-61
        } else if (i == '-') {
            char_map[i] = 62;  // '-': 62
        } else if (i == '.') {
            char_map[i] = 63;  // '.': 63
        } else {
            char_map[i] = -1;  // 其他字符: -1
        }
    }
}

// 辅助函数：将域名转换为小写并移除末尾的点号
void normalizeDomain(char* normalized, const char* domain, size_t size) {
    if (!normalized || !domain || size == 0) return;
    
    memset(normalized, 0, size);  // 初始化为0
    size_t len = strlen(domain);
    size_t i;
    for (i = 0; i < len && i < size - 1; i++) {
        normalized[i] = tolower(domain[i]);
    }
    // 移除末尾的点号
    if (i > 0 && normalized[i-1] == '.') {
        i--;
    }
    normalized[i] = '\0';
}

// Trie树相关函数实现
struct TrieNode* createTrieNode() {
    struct TrieNode* node = (struct TrieNode*)malloc(sizeof(struct TrieNode));
    if (node) {
        node->is_end = 0;
        memset(node->ip, 0, sizeof(node->ip));
        for (int i = 0; i < MAX_CHILDREN; i++) {
            node->children[i] = NULL;
        }
    }
    return node;
}

void insertTrie(struct TrieNode* root, const char* domain, const uint8_t* ip) {
    if (!root || !domain || !ip) return;

    // 初始化字符映射表
    static int initialized = 0;
    if (!initialized) {
        initCharMap();
        initialized = 1;
    }

    struct TrieNode* current = root;
    for (int i = 0; domain[i]; i++) {
        int index = char_map[(unsigned char)domain[i]];
        if (index == -1) continue;  // 跳过无效字符

        if (!current->children[index]) {
            current->children[index] = createTrieNode();
        }
        current = current->children[index];
    }

    // 设置域名结尾标记和IPv4地址
    current->is_end = 1;
    memcpy(current->ip, ip, 4);
}

int searchTrie(struct TrieNode* root, const char* domain) {
    if (!root || !domain) {
        return -1;
    }

    // 初始化字符映射表
    static int initialized = 0;
    if (!initialized) {
        initCharMap();
        initialized = 1;
    }

    struct TrieNode* current = root;
    char normalized[256];
    normalizeDomain(normalized, domain, sizeof(normalized));
    int len = strlen(normalized);
    
    // 从后向前搜索
    for (int i = len - 1; i >= 0; i--) {
        int index = char_map[(unsigned char)normalized[i]];
        if (index == -1) continue;  // 跳过无效字符

        if (!current->children[index]) {
            return -1;
        }
        current = current->children[index];
    }
    
    // 只有当节点是终点时才返回成功
    return current->is_end ? 1 : -1;
}

int getIPFromTrie(struct TrieNode* root, const char* domain, uint8_t** ip, int* ip_len) {
    if (!root || !domain || !ip || !ip_len) return 0;

    // 初始化字符映射表
    static int initialized = 0;
    if (!initialized) {
        initCharMap();
        initialized = 1;
    }

    struct TrieNode* current = root;
    for (int i = 0; domain[i]; i++) {
        int index = char_map[(unsigned char)domain[i]];
        if (index == -1) continue;  // 跳过无效字符

        if (!current->children[index]) {
            return 0;  // 域名不存在
        }
        current = current->children[index];
    }

    if (current->is_end) {
        // 分配内存并复制IPv4地址
        *ip = (uint8_t*)malloc(4);
        if (!*ip) {
            *ip_len = 0;
            return 0;
        }
        memset(*ip, 0, 4);  // 初始化为0
        memcpy(*ip, current->ip, 4);
        *ip_len = 4;
        return 1;
    }

    return 0;  // 域名不存在
}

void freeTrie(struct TrieNode* root) {
    if (!root) return;

    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (root->children[i]) {
            freeTrie(root->children[i]);
        }
    }

    free(root);
}
