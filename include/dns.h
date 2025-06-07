#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <winsock2.h>
#include <windows.h>

// DNS 常量定义
#define BUFFER_SIZE 1024
#define MAX_ID_LIST 65536
#define EXPIRE_TIME 30
#define DNS_CLASS_IN 1
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_RCODE_NO_ERROR 0
#define DNS_RCODE_NAME_ERROR 3

// DNS 消息结构
struct DNS_HEADER {
    uint16_t ID;
    uint8_t QR;
    uint8_t OPCODE;
    uint8_t AA;
    uint8_t TC;
    uint8_t RD;
    uint8_t RA;
    uint8_t Z;
    uint8_t RCODE;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
};

struct DNS_QUESTION {
    char QNAME[300];
    uint16_t QTYPE;
    uint16_t QCLASS;
};

struct DNS_RR {
    char NAME[300];
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    uint16_t RDLENGTH;
    uint8_t* RDATA;
};

struct DNS_DATA {
    struct DNS_HEADER header;
    struct DNS_QUESTION* question;
    struct DNS_RR* answer;
    struct DNS_RR* authority;
    struct DNS_RR* additional;
};

// 全局变量声明
extern SOCKET client_socket;
extern SOCKET server_socket;
extern struct sockaddr_in client_addr;
extern struct sockaddr_in server_addr;
extern int debug_mode;

// ID转换映射结构体
struct IDMapEntry {
    uint16_t client_id;           // 客户端原始ID
    uint16_t forward_id;          // 转发到上游的ID
    struct sockaddr_in client_addr; // 客户端地址
    time_t timestamp;             // 映射创建时间
    int valid;
};

#define MAX_ID_MAP 1024

extern struct IDMapEntry id_map_table[MAX_ID_MAP];

// DNS 相关函数声明
void parseDNSMessage(char recv_buffer[], struct DNS_DATA* dns_msg);
void setDNSResponse(struct DNS_DATA* dns_msg, uint8_t ip_addr[], char name[], uint16_t QTYPE);
void setNoDomainResponse(struct DNS_DATA* dns_msg);
int formatDNSMessage(char ansTo_buffer[], struct DNS_DATA* dns_msg);
void logDNSMessage(const struct DNS_DATA* dns_msg);
void cleanupDNSData(struct DNS_DATA* dns_data);
void get_domain_name(char * const recv_buffer, char* domain_name, char* ptr, int n, char** init_ptr, char can_plus_ptr);

// ID转换相关函数声明
uint16_t allocate_forward_id(uint16_t client_id, struct sockaddr_in* client_addr);
int find_and_remove_client_id(uint16_t forward_id, uint16_t* client_id, struct sockaddr_in* client_addr);
void cleanup_id_map();

#endif // DNS_H
