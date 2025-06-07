#include "../include/dns.h"
#include "../include/cache.h"
#include "../include/trie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// 添加函数声明
const char* WSAAPI inet_ntop(int af, const void* src, char* dst, socklen_t size);
int WSAAPI inet_pton(int af, const char* src, void* dst);

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT 53
#define DEFAULT_CACHE_SIZE 1000

// 全局变量定义
SOCKET client_socket = INVALID_SOCKET;
SOCKET server_socket = INVALID_SOCKET;
struct sockaddr_in client_addr = {0};
struct sockaddr_in server_addr = {0};
int debug_mode = 0;
struct TrieNode* trie_root = NULL;  // 添加Trie树根节点

// 函数声明
void initWinsock();
void cleanupWinsock();
void handleDNSRequest(char* recv_buffer, int recv_len);
void forwardToServer(char* recv_buffer, int recv_len, char* ansTo_buffer, int* ansTo_len);

// 添加文件操作函数声明
void writeToDNSRelayFile(const char* domain, const uint8_t* ip, int ip_len);
void loadDNSRelayFile();

int main(int argc, char* argv[]) {
    // 初始化Winsock
    initWinsock();

    // 解析命令行参数
    int port = DEFAULT_PORT;
    int cache_size = DEFAULT_CACHE_SIZE;
    debug_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            cache_size = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-d") == 0) {
            debug_mode = 1;
        } else if (strcmp(argv[i], "-dd") == 0) {
            debug_mode = 2;
        }
    }

    // 初始化缓存和Trie树
    initCache(cache_size);
    trie_root = createTrieNode();  // 初始化Trie树根节点

    // 从dnsrelay.txt加载数据到Trie树
    loadDNSRelayFile();

    // 创建客户端socket
    client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client_socket == INVALID_SOCKET) {
        printf("Failed to create client socket\n");
        cleanupWinsock();
        return 1;
    }

    // 绑定客户端socket
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(port);

    if (bind(client_socket, (struct sockaddr*)&client_addr, sizeof(client_addr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        printf("Failed to bind client socket on port %d. Error code: %d\n", port, error);
        if (error == WSAEACCES) {
            printf("Error: Access denied. Try running as administrator or use a port number above 1024.\n");
        } else if (error == WSAEADDRINUSE) {
            printf("Error: Port %d is already in use. Try a different port.\n", port);
        }
        closesocket(client_socket);
        cleanupWinsock();
        return 1;
    }

    // 创建服务器socket
    server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_socket == INVALID_SOCKET) {
        printf("Failed to create server socket\n");
        closesocket(client_socket);
        cleanupWinsock();
        return 1;
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    inet_pton(AF_INET, "10.3.9.6", &server_addr.sin_addr);

    printf("DNS Relay Server started on port %d\n", port);
    printf("Cache size: %d\n", cache_size);
    printf("Debug mode: %d\n", debug_mode);

    // 主循环
    char recv_buffer[BUFFER_SIZE];
    char ansTo_buffer[BUFFER_SIZE];
    int recv_len;
    int client_addr_len = sizeof(client_addr);

    while (1) {
        // 接收DNS请求
        recv_len = recvfrom(client_socket, recv_buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_addr_len);
        if (recv_len == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK) {
                // 非阻塞模式下，没有数据可读
                continue;
            }
            printf("Failed to receive data. Error code: %d\n", error);
            continue;
        }

        if (debug_mode > 0) {
            char client_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            printf("Received %d bytes from %s:%d\n", recv_len, client_ip, ntohs(client_addr.sin_port));
        }

        // 处理DNS请求
        handleDNSRequest(recv_buffer, recv_len);
    }

    // 清理资源
    closesocket(client_socket);
    closesocket(server_socket);
    cleanupCache();
    freeTrie(trie_root);  // 清理Trie树
    cleanupWinsock();

    return 0;
}

void initWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Failed to initialize Winsock\n");
        exit(1);
    }
}

void cleanupWinsock() {
    WSACleanup();
}

void handleDNSRequest(char* recv_buffer, int recv_len) {
    struct DNS_DATA dns_msg;
    memset(&dns_msg, 0, sizeof(dns_msg));

    // 解析DNS消息
    parseDNSMessage(recv_buffer, &dns_msg);

    // 记录DNS消息
    logDNSMessage(&dns_msg);

    // 保存原始域名
    char original_domain[256] = {0};
    strncpy(original_domain, dns_msg.question[0].QNAME, sizeof(original_domain) - 1);
    original_domain[sizeof(original_domain) - 1] = '\0';

    // 1. 首先检查Trie树（用于域名拦截，无论IPv4还是IPv6）
    uint8_t* trie_ip = NULL;
    int trie_ip_len = 0;
    // 对于所有查询类型都检查Trie树
    if (getIPFromTrie(trie_root, dns_msg.question[0].QNAME, &trie_ip, &trie_ip_len)) {
        if (debug_mode > 0) {
            printf("Trie hit for domain: %s\n", dns_msg.question[0].QNAME);
            char ip_str[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, trie_ip, ip_str, INET_ADDRSTRLEN);
            printf("Found IP in Trie: %s (search mode: %s)\n", ip_str, 
                   dns_msg.question[0].QTYPE == DNS_TYPE_A ? "IPv4" : "IPv6");
        }
        // 检查是否为0.0.0.0（不良网站拦截）- 对所有查询类型都进行拦截
        if (trie_ip_len == 4 && trie_ip[0] == 0 && trie_ip[1] == 0 && trie_ip[2] == 0 && trie_ip[3] == 0) {
            if (debug_mode > 0) {
                printf("Blocked site detected (0.0.0.0), returning NXDOMAIN for domain: %s (Query type: %s)\n", 
                       dns_msg.question[0].QNAME, 
                       dns_msg.question[0].QTYPE == DNS_TYPE_A ? "A" : "AAAA");
            }
            dns_msg.header.RCODE = DNS_RCODE_NAME_ERROR;
            dns_msg.header.ANCOUNT = 0;
            dns_msg.header.NSCOUNT = 0;
            dns_msg.header.ARCOUNT = 0;
            char ansTo_buffer[BUFFER_SIZE] = {0};
            int ansTo_len = formatDNSMessage(ansTo_buffer, &dns_msg);
            sendto(client_socket, ansTo_buffer, ansTo_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
            if (trie_ip) {
                free(trie_ip);
            }
            cleanupDNSData(&dns_msg);
            return;
        }
        // 如果是IPv4查询且Trie树中有记录，使用Trie树中的IP
        if (dns_msg.question[0].QTYPE == DNS_TYPE_A) {
            setDNSResponse(&dns_msg, trie_ip, dns_msg.question[0].QNAME, dns_msg.question[0].QTYPE);
            if (trie_ip) {
                free(trie_ip);
                trie_ip = NULL;
            }
            char ansTo_buffer[BUFFER_SIZE] = {0};
            int ansTo_len = formatDNSMessage(ansTo_buffer, &dns_msg);
            sendto(client_socket, ansTo_buffer, ansTo_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
            cleanupDNSData(&dns_msg);
            return;
        }
        // 如果是IPv6查询，继续检查缓存或转发到服务器
        if (trie_ip) {
            free(trie_ip);
            trie_ip = NULL;
        }
    }

    // 2. 如果Trie树未命中或不是IPv4查询，检查缓存
    uint8_t* cached_ip = NULL;
    int cached_ip_len = 0;
    if (findInCache(dns_msg.question[0].QNAME, &cached_ip, &cached_ip_len)) {
        if (debug_mode > 0) {
            printf("Cache hit for domain: %s\n", dns_msg.question[0].QNAME);
        }
        // 检查是否为0.0.0.0（不良网站拦截）
        if (cached_ip_len == 4 && cached_ip[0] == 0 && cached_ip[1] == 0 && cached_ip[2] == 0 && cached_ip[3] == 0) {
            if (debug_mode > 0) {
                printf("Blocked site detected (0.0.0.0), returning NXDOMAIN for domain: %s (Query type: %s)\n", 
                       dns_msg.question[0].QNAME,
                       dns_msg.question[0].QTYPE == DNS_TYPE_A ? "A" : "AAAA");
            }
            dns_msg.header.RCODE = DNS_RCODE_NAME_ERROR;
            dns_msg.header.ANCOUNT = 0;
            dns_msg.header.NSCOUNT = 0;
            dns_msg.header.ARCOUNT = 0;
            char ansTo_buffer[BUFFER_SIZE] = {0};
            int ansTo_len = formatDNSMessage(ansTo_buffer, &dns_msg);
            sendto(client_socket, ansTo_buffer, ansTo_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
            if (cached_ip) {
                free(cached_ip);
            }
            cleanupDNSData(&dns_msg);
            return;
        }
        setDNSResponse(&dns_msg, cached_ip, dns_msg.question[0].QNAME, dns_msg.question[0].QTYPE);
        if (cached_ip) {
            free(cached_ip);
            cached_ip = NULL;
        }
        char ansTo_buffer[BUFFER_SIZE] = {0};
        int ansTo_len = formatDNSMessage(ansTo_buffer, &dns_msg);
        sendto(client_socket, ansTo_buffer, ansTo_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
        cleanupDNSData(&dns_msg);
        return;
    }

    // 3. 如果缓存也未命中，转发到服务器
    if (debug_mode > 0) {
        printf("Cache miss for domain: %s, forwarding to server\n", dns_msg.question[0].QNAME);
    }
    
    char ansTo_buffer[BUFFER_SIZE] = {0};
    int ansTo_len = 0;
    forwardToServer(recv_buffer, recv_len, ansTo_buffer, &ansTo_len);

    // 解析服务器响应
    struct DNS_DATA server_response;
    memset(&server_response, 0, sizeof(server_response));
    parseDNSMessage(ansTo_buffer, &server_response);

    // 如果响应成功，更新缓存和文件（仅IPv4）
    if (server_response.header.RCODE == DNS_RCODE_NO_ERROR && server_response.header.ANCOUNT > 0) {
        for (int i = 0; i < server_response.header.ANCOUNT; i++) {
            if (server_response.answer[i].TYPE == DNS_TYPE_A || server_response.answer[i].TYPE == DNS_TYPE_AAAA) {
                // 检查A记录是否为0.0.0.0（不良网站拦截）
                if (server_response.answer[i].TYPE == DNS_TYPE_A && server_response.answer[i].RDLENGTH == 4 &&
                    server_response.answer[i].RDATA[0] == 0 && server_response.answer[i].RDATA[1] == 0 &&
                    server_response.answer[i].RDATA[2] == 0 && server_response.answer[i].RDATA[3] == 0) {
                    if (debug_mode > 0) {
                        printf("Blocked site detected (0.0.0.0) from upstream, returning NXDOMAIN for domain: %s (Query type: %s)\n", 
                               original_domain,
                               dns_msg.question[0].QTYPE == DNS_TYPE_A ? "A" : "AAAA");
                    }
                    server_response.header.RCODE = DNS_RCODE_NAME_ERROR;
                    server_response.header.ANCOUNT = 0;
                    server_response.header.NSCOUNT = 0;
                    server_response.header.ARCOUNT = 0;
                    char nxdomain_buffer[BUFFER_SIZE] = {0};
                    int nxdomain_len = formatDNSMessage(nxdomain_buffer, &server_response);
                    sendto(client_socket, nxdomain_buffer, nxdomain_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
                    cleanupDNSData(&server_response);
                    return;
                }
                // 更新缓存（所有类型）
                updateCache(original_domain, server_response.answer[i].RDATA, 
                          server_response.answer[i].RDLENGTH, server_response.answer[i].TTL);
                // 只对IPv4地址写入文件
                if (server_response.answer[i].TYPE == DNS_TYPE_A) {
                    writeToDNSRelayFile(original_domain, server_response.answer[i].RDATA, 
                                      server_response.answer[i].RDLENGTH);
                }
            }
        }
    }

    // 发送服务器响应给客户端
    sendto(client_socket, ansTo_buffer, ansTo_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
    cleanupDNSData(&server_response);
    cleanupDNSData(&dns_msg);
}

void forwardToServer(char* recv_buffer, int recv_len, char* ansTo_buffer, int* ansTo_len) {
    // 解析原始ID
    uint16_t client_id = ntohs(*(uint16_t*)recv_buffer);
    // 分配新的forward_id并记录映射
    uint16_t forward_id = allocate_forward_id(client_id, &client_addr);
    if (debug_mode > 0) {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("[ID MAP] Alloc: client_id=0x%04x -> forward_id=0x%04x, client: %s:%d\n", client_id, forward_id, client_ip, ntohs(client_addr.sin_port));
    }
    *(uint16_t*)recv_buffer = htons(forward_id);

    // 发送请求到DNS服务器
    if (sendto(server_socket, recv_buffer, recv_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Failed to send data to server\n");
        return;
    }

    // 接收服务器响应
    int server_addr_len = sizeof(server_addr);
    *ansTo_len = recvfrom(server_socket, ansTo_buffer, BUFFER_SIZE, 0, (struct sockaddr*)&server_addr, &server_addr_len);
    if (*ansTo_len == SOCKET_ERROR) {
        printf("Failed to receive data from server\n");
        return;
    }

    // 收到响应后，恢复原始ID
    uint16_t resp_forward_id = ntohs(*(uint16_t*)ansTo_buffer);
    uint16_t resp_client_id;
    struct sockaddr_in resp_client_addr;
    if (find_and_remove_client_id(resp_forward_id, &resp_client_id, &resp_client_addr)) {
        if (debug_mode > 0) {
            char resp_client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &resp_client_addr.sin_addr, resp_client_ip, INET_ADDRSTRLEN);
            printf("[ID MAP] Restore: forward_id=0x%04x -> client_id=0x%04x, client: %s:%d\n", resp_forward_id, resp_client_id, resp_client_ip, ntohs(resp_client_addr.sin_port));
        }
        *(uint16_t*)ansTo_buffer = htons(resp_client_id);
        // 发送回原客户端
        sendto(client_socket, ansTo_buffer, *ansTo_len, 0, (struct sockaddr*)&resp_client_addr, sizeof(resp_client_addr));
    } else {
        // 没找到映射，丢弃
        if (debug_mode > 0) {
            printf("[ID MAP] No mapping found, drop response: forward_id=0x%04x\n", resp_forward_id);
        }
    }
}

// 添加文件写入函数实现
void writeToDNSRelayFile(const char* domain, const uint8_t* ip, int ip_len) {
    // 只处理IPv4地址
    if (ip_len != 4) {
        if (debug_mode > 0) {
            printf("Skipping IPv6 address\n");
        }
        return;
    }

    // 将IP地址转换为字符串格式
    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, ip, 4);
    
    if (inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN) == NULL) {
        if (debug_mode > 0) {
            printf("Failed to convert IPv4 address\n");
        }
        return;
    }

    // 确保域名以点号结尾
    char domain_with_dot[256];
    strncpy(domain_with_dot, domain, sizeof(domain_with_dot) - 2);
    domain_with_dot[sizeof(domain_with_dot) - 2] = '\0';
    if (domain_with_dot[strlen(domain_with_dot) - 1] != '.') {
        strcat(domain_with_dot, ".");
    }

    // 创建临时文件
    FILE* temp_file = fopen("dnsrelay.txt.tmp", "w");
    if (temp_file == NULL) {
        if (debug_mode > 0) {
            printf("Failed to create temporary file\n");
        }
        return;
    }

    // 读取原文件并更新记录
    FILE* original_file = fopen("dnsrelay.txt", "r");
    if (original_file != NULL) {
        char line[256];
        int updated = 0;
        
        while (fgets(line, sizeof(line), original_file)) {
            char existing_domain[256];
            char existing_ip[INET_ADDRSTRLEN];
            
            if (sscanf(line, "%s %s", existing_domain, existing_ip) == 2) {
                // 确保现有域名以点号结尾
                char existing_domain_with_dot[256];
                strncpy(existing_domain_with_dot, existing_domain, sizeof(existing_domain_with_dot) - 2);
                existing_domain_with_dot[sizeof(existing_domain_with_dot) - 2] = '\0';
                if (existing_domain_with_dot[strlen(existing_domain_with_dot) - 1] != '.') {
                    strcat(existing_domain_with_dot, ".");
                }
                
                if (strcasecmp(domain_with_dot, existing_domain_with_dot) == 0) {
                    // 更新记录
                    fprintf(temp_file, "%s %s\n", domain_with_dot, ip_str);
                    updated = 1;
                    if (debug_mode > 0) {
                        printf("Updated record in dnsrelay.txt: %s %s\n", domain_with_dot, ip_str);
                    }
                } else {
                    // 保持原记录不变
                    fprintf(temp_file, "%s", line);
                }
            }
        }
        fclose(original_file);
        
        // 如果没有找到匹配的记录，添加新记录
        if (!updated) {
            fprintf(temp_file, "%s %s\n", domain_with_dot, ip_str);
            if (debug_mode > 0) {
                printf("Added new record to dnsrelay.txt: %s %s\n", domain_with_dot, ip_str);
            }
        }
    } else {
        // 如果原文件不存在，直接写入新记录
        fprintf(temp_file, "%s %s\n", domain_with_dot, ip_str);
        if (debug_mode > 0) {
            printf("Created new dnsrelay.txt with record: %s %s\n", domain_with_dot, ip_str);
        }
    }
    
    fclose(temp_file);
    
    // 替换原文件
    remove("dnsrelay.txt");
    rename("dnsrelay.txt.tmp", "dnsrelay.txt");
}

// 添加函数实现
void loadDNSRelayFile() {
    FILE* file = fopen("dnsrelay.txt", "r");
    if (!file) {
        if (debug_mode > 0) {
            printf("Failed to open dnsrelay.txt\n");
        }
        return;
    }

    char line[512];
    char domain[256];
    char ip_str[INET6_ADDRSTRLEN];
    uint8_t ip[16];
    int is_ipv6;

    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%s %s", domain, ip_str) == 2) {
            // Check if it's an IPv4 address
            struct in_addr addr4;
            if (inet_pton(AF_INET, ip_str, &addr4) == 1) {
                memcpy(ip, &addr4, sizeof(addr4));
                insertTrie(trie_root, domain, ip);
            } else {
                // Potentially an IPv6 address or invalid format, skip for Trie insertion as per current logic
                if (debug_mode > 0) {
                    // printf("Skipping non-IPv4 or invalid address for Trie: %s %s\n", domain, ip_str);
                }
            }
        }
    }

    fclose(file);
    
    if (debug_mode > 0) {
        printf("Loaded records from dnsrelay.txt\n");
    }
}