#include "../include/dns.h"
#include "../include/cache.h"
#include "../include/trie.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// 全局变量定义
SOCKET client_socket;
SOCKET server_socket;
struct sockaddr_in client_addr;
struct sockaddr_in server_addr;
int debug_mode;

struct IDMapEntry id_map_table[MAX_ID_MAP] = {0};

// DNS相关函数实现
void get_domain_name(char * const recv_buffer, char* domain_name, char* ptr, int n, char** init_ptr, char can_plus_ptr) {
    if ((ptr)[0] == 0) {
        if (can_plus_ptr == 1)
            (*init_ptr)++;
        return;
    }
    if (((ptr)[0] & 0xc0) == 0xc0) {
        unsigned short offset = (((unsigned char)(ptr[0]) & 0x3f) << 8) + (unsigned char)(ptr[1]);
        if (can_plus_ptr == 1)
            (*init_ptr) += 2;
        char* temp_ptr1 = recv_buffer + offset;
        get_domain_name(recv_buffer, domain_name, temp_ptr1, n, init_ptr, 0);
        return;
    }
    int len = (ptr)[0];
    if (can_plus_ptr == 1)
        (*init_ptr) += (len + 1);
    for (int i = 0; i < len; i++) {
        domain_name[n + i] = (char)(ptr)[i + 1];
    }
    domain_name[n + len] = '.';
    char* temp_ptr2 = ptr + len + 1;
    get_domain_name(recv_buffer, domain_name, temp_ptr2, n + len + 1, init_ptr, can_plus_ptr);
}

void parseDNSMessage(char recv_buffer[], struct DNS_DATA* dns_msg) {
    //DNS_HEADER
    dns_msg->header.ID = ntohs(*(uint16_t*)recv_buffer);
    dns_msg->header.QR = (recv_buffer[2] >> 7) & 0x01;
    dns_msg->header.OPCODE = (recv_buffer[2] >> 3) & 0x0F;
    dns_msg->header.AA = (recv_buffer[2] >> 2) & 0x01;
    dns_msg->header.TC = (recv_buffer[2] >> 1) & 0x01;
    dns_msg->header.RD = recv_buffer[2] & 0x01;
    dns_msg->header.RA = (recv_buffer[3] >> 7) & 0x01;
    dns_msg->header.Z = (recv_buffer[3] >> 4) & 0x07;
    dns_msg->header.RCODE = recv_buffer[3] & 0x0F;
    dns_msg->header.QDCOUNT = (recv_buffer[4] << 8) + recv_buffer[5];
    dns_msg->header.ANCOUNT = (recv_buffer[6] << 8) + recv_buffer[7];
    dns_msg->header.NSCOUNT = (recv_buffer[8] << 8) + recv_buffer[9];
    dns_msg->header.ARCOUNT = (recv_buffer[10] << 8) + recv_buffer[11];

    // 动态分配DNS_QUESTION数组
    dns_msg->question = (struct DNS_QUESTION*)malloc(dns_msg->header.QDCOUNT * sizeof(struct DNS_QUESTION));
    if (!dns_msg->question) {
        printf("Memory allocation failed for DNS questions.\n");
        return;
    }
    if(dns_msg->header.QDCOUNT == 0)
        dns_msg->question = NULL;

    char *ptr_from_question = recv_buffer + 12;
    for (int i = 0; i < dns_msg->header.QDCOUNT; i++) {
        memset(dns_msg->question[i].QNAME, 0, sizeof(dns_msg->question[i].QNAME));
        get_domain_name(recv_buffer, dns_msg->question[i].QNAME, ptr_from_question, 0, &ptr_from_question, 1);
        dns_msg->question[i].QTYPE = ntohs(*(uint16_t*)ptr_from_question);
        dns_msg->question[i].QCLASS = ntohs(*(uint16_t*)(ptr_from_question + 2));
        ptr_from_question += 4;
    }

    //DNS_ANSWER
    dns_msg->answer = (struct DNS_RR*)malloc(dns_msg->header.ANCOUNT * sizeof(struct DNS_RR));
    if (!dns_msg->answer) {
        printf("Memory allocation failed for DNS answers.\n");
        return;
    }
    if(dns_msg->header.ANCOUNT == 0)
        dns_msg->answer = NULL;

    char *ptr_from_answer = ptr_from_question;
    for (int i = 0; i < dns_msg->header.ANCOUNT; i++) {
        memset(dns_msg->answer[i].NAME, 0, sizeof(dns_msg->answer[i].NAME));
        get_domain_name(recv_buffer, dns_msg->answer[i].NAME, ptr_from_answer, 0, &ptr_from_answer, 1);
        dns_msg->answer[i].TYPE = ntohs(*(uint16_t*)ptr_from_answer);
        dns_msg->answer[i].CLASS = ntohs(*(uint16_t*)(ptr_from_answer + 2));
        dns_msg->answer[i].TTL = ntohl(*(uint32_t*)(ptr_from_answer + 4));
        ptr_from_answer += 8;

        dns_msg->answer[i].RDLENGTH = ntohs(*(uint16_t*)ptr_from_answer);
        dns_msg->answer[i].RDATA = (uint8_t*)malloc(dns_msg->answer[i].RDLENGTH);
        if (!dns_msg->answer[i].RDATA) {
            printf("Memory allocation failed for DNS RDATA.\n");
            return;
        }
        memcpy(dns_msg->answer[i].RDATA, ptr_from_answer + 2, dns_msg->answer[i].RDLENGTH);
        if(dns_msg->answer[i].RDLENGTH == 0)
            dns_msg->answer[i].RDATA = NULL;
        ptr_from_answer += 2 + dns_msg->answer[i].RDLENGTH;
    }

    //DNS_AUTHORITY
    dns_msg->authority = (struct DNS_RR*)malloc(dns_msg->header.NSCOUNT * sizeof(struct DNS_RR));
    if (!dns_msg->authority) {
        printf("Memory allocation failed for DNS authority.\n");
        return;
    }
    if(dns_msg->header.NSCOUNT == 0)
        dns_msg->authority = NULL;

    char *ptr_from_authority = ptr_from_answer;
    for (int i = 0; i < dns_msg->header.NSCOUNT; i++) {
        memset(dns_msg->authority[i].NAME, 0, sizeof(dns_msg->authority[i].NAME));
        get_domain_name(recv_buffer, dns_msg->authority[i].NAME, ptr_from_authority, 0, &ptr_from_authority, 1);
        dns_msg->authority[i].TYPE = ntohs(*(uint16_t*)ptr_from_authority);
        dns_msg->authority[i].CLASS = ntohs(*(uint16_t*)(ptr_from_authority + 2));
        dns_msg->authority[i].TTL = ntohl(*(uint32_t*)(ptr_from_authority + 4));
        ptr_from_authority += 8;

        dns_msg->authority[i].RDLENGTH = ntohs(*(uint16_t*)ptr_from_authority);
        dns_msg->authority[i].RDATA = (uint8_t*)malloc(dns_msg->authority[i].RDLENGTH);
        if (!dns_msg->authority[i].RDATA) {
            printf("Memory allocation failed for DNS RDATA.\n");
            return;
        }
        memcpy(dns_msg->authority[i].RDATA, ptr_from_authority + 2, dns_msg->authority[i].RDLENGTH);
        if(dns_msg->authority[i].RDLENGTH == 0)
            dns_msg->authority[i].RDATA = NULL;
        ptr_from_authority += 2 + dns_msg->authority[i].RDLENGTH;
    }

    //DNS_ADDITIONAL
    dns_msg->additional = (struct DNS_RR*)malloc(dns_msg->header.ARCOUNT * sizeof(struct DNS_RR));
    if (!dns_msg->additional) {
        printf("Memory allocation failed for DNS additional.\n");
        return;
    }
    if(dns_msg->header.ARCOUNT == 0)
        dns_msg->additional = NULL;

    char *ptr_from_additional = ptr_from_authority;
    for (int i = 0; i < dns_msg->header.ARCOUNT; i++) {
        memset(dns_msg->additional[i].NAME, 0, sizeof(dns_msg->additional[i].NAME));
        get_domain_name(recv_buffer, dns_msg->additional[i].NAME, ptr_from_additional, 0, &ptr_from_additional, 1);
        dns_msg->additional[i].TYPE = ntohs(*(uint16_t*)ptr_from_additional);
        dns_msg->additional[i].CLASS = ntohs(*(uint16_t*)(ptr_from_additional + 2));
        dns_msg->additional[i].TTL = ntohl(*(uint32_t*)(ptr_from_additional + 4));
        ptr_from_additional += 8;

        dns_msg->additional[i].RDLENGTH = ntohs(*(uint16_t*)ptr_from_additional);
        dns_msg->additional[i].RDATA = (uint8_t*)malloc(dns_msg->additional[i].RDLENGTH);
        if (!dns_msg->additional[i].RDATA) {
            printf("Memory allocation failed for DNS RDATA.\n");
            return;
        }
        memcpy(dns_msg->additional[i].RDATA, ptr_from_additional + 2, dns_msg->additional[i].RDLENGTH);
        if(dns_msg->additional[i].RDLENGTH == 0)
            dns_msg->additional[i].RDATA = NULL;
        ptr_from_additional += 2 + dns_msg->additional[i].RDLENGTH;
    }
}

void setDNSResponse(struct DNS_DATA* dns_msg, uint8_t ip_addr[], char name[], uint16_t QTYPE) {
    // 检查是否是IPv4地址0.0.0.0
    if (QTYPE == DNS_TYPE_A && ip_addr[0] == 0 && ip_addr[1] == 0 && ip_addr[2] == 0 && ip_addr[3] == 0) {
        // 设置域名不存在的响应
        dns_msg->header.QR = 1;      // 这是一个响应
        dns_msg->header.AA = 1;      // 授权回答
        dns_msg->header.RA = 1;      // 递归可用
        dns_msg->header.RCODE = DNS_RCODE_NAME_ERROR; // 域名不存在
        dns_msg->header.ANCOUNT = 0; // 没有回答记录
        dns_msg->header.NSCOUNT = 0; // 没有授权记录
        dns_msg->header.ARCOUNT = 0; // 没有附加记录

        if (debug_mode > 0) {
            printf("Blocking domain: %s (IPv4 address is 0.0.0.0)\n", name);
            printf("Returning NXDOMAIN response\n");
        }
        return;
    }

    // 设置响应标志
    dns_msg->header.QR = 1;      // 这是一个响应
    dns_msg->header.AA = 1;      // 授权回答
    dns_msg->header.RA = 1;      // 递归可用
    dns_msg->header.RCODE = DNS_RCODE_NO_ERROR;
    dns_msg->header.ANCOUNT = 1; // 一个回答记录
    dns_msg->header.NSCOUNT = 0; // 没有授权记录
    dns_msg->header.ARCOUNT = 0; // 没有附加记录

    // 分配回答记录空间
    if(dns_msg->answer == NULL) {
        dns_msg->answer = malloc(sizeof(struct DNS_RR));
    } else {
        dns_msg->answer = realloc(dns_msg->answer, sizeof(struct DNS_RR));
    }

    if (!dns_msg->answer) {
        printf("Failed to allocate memory for DNS answer\n");
        return;
    }

    // 设置回答记录
    strncpy(dns_msg->answer[0].NAME, name, sizeof(dns_msg->answer[0].NAME) - 1);
    dns_msg->answer[0].NAME[sizeof(dns_msg->answer[0].NAME) - 1] = '\0';
    dns_msg->answer[0].TYPE = QTYPE;
    dns_msg->answer[0].CLASS = DNS_CLASS_IN;
    dns_msg->answer[0].TTL = 300; // 5分钟TTL
    dns_msg->answer[0].RDLENGTH = (QTYPE == DNS_TYPE_AAAA) ? 16 : 4;
    
    // 分配并复制IP地址
    dns_msg->answer[0].RDATA = malloc(dns_msg->answer[0].RDLENGTH);
    if (!dns_msg->answer[0].RDATA) {
        printf("Failed to allocate memory for RDATA\n");
        return;
    }
    memcpy(dns_msg->answer[0].RDATA, ip_addr, dns_msg->answer[0].RDLENGTH);

    if (debug_mode > 0) {
        printf("Set DNS response for domain: %s\n", name);
        printf("Response type: %s\n", (QTYPE == DNS_TYPE_AAAA) ? "AAAA" : "A");
        printf("TTL: %d\n", dns_msg->answer[0].TTL);
        printf("IP length: %d\n", dns_msg->answer[0].RDLENGTH);
    }
}

void setNoDomainResponse(struct DNS_DATA* dns_msg) {
    dns_msg->header.QR = 1;
    dns_msg->header.RCODE = DNS_RCODE_NAME_ERROR;
}

int formatDNSMessage(char ansTo_buffer[], struct DNS_DATA* dns_msg) {
    int total_len = 0;
    //设置DNS_HEADER
    *(uint16_t*)(ansTo_buffer) = htons(dns_msg->header.ID);
    ansTo_buffer[2] = (dns_msg->header.QR << 7) + (dns_msg->header.OPCODE << 3) + (dns_msg->header.AA << 2) + (dns_msg->header.TC << 1) + dns_msg->header.RD;
    ansTo_buffer[3] = (dns_msg->header.RA << 7) + (dns_msg->header.Z << 4) + dns_msg->header.RCODE;
    *(uint16_t*)(ansTo_buffer + 4) = htons(dns_msg->header.QDCOUNT);
    *(uint16_t*)(ansTo_buffer + 6) = htons(dns_msg->header.ANCOUNT);
    *(uint16_t*)(ansTo_buffer + 8) = htons(dns_msg->header.NSCOUNT);
    *(uint16_t*)(ansTo_buffer + 10) = htons(dns_msg->header.ARCOUNT);
    total_len += 12;

    //设置DNS_QUESTION
    char *ptr_to_question = ansTo_buffer + 12;
    for (int i = 0; i < dns_msg->header.QDCOUNT; i++) {
        char *ptr_to_name = dns_msg->question[i].QNAME;
        int name_len = strlen(ptr_to_name);
        int pos = 0;
        while (pos < name_len) {
            int label_len = strchr(ptr_to_name + pos, '.') - (ptr_to_name + pos);
            *ptr_to_question++ = label_len;
            memcpy(ptr_to_question, ptr_to_name + pos, label_len);
            ptr_to_question += label_len;
            pos += label_len + 1;
        }
        *ptr_to_question++ = 0;
        *(uint16_t*)ptr_to_question = htons(dns_msg->question[i].QTYPE);
        ptr_to_question += 2;
        *(uint16_t*)ptr_to_question = htons(dns_msg->question[i].QCLASS);
        ptr_to_question += 2;

        total_len += name_len + 1 + 2 + 2;
    }   

    //设置DNS_ANSWER
    char *ptr_to_answer = ptr_to_question;
    for (int i = 0; i < dns_msg->header.ANCOUNT; i++) {
        char *ptr_to_name = dns_msg->answer[i].NAME;
        int name_len = strlen(ptr_to_name);
        int pos = 0;
        while (pos < name_len) {
            int label_len = strchr(ptr_to_name + pos, '.') - (ptr_to_name + pos);
            *ptr_to_answer++ = label_len;
            memcpy(ptr_to_answer, ptr_to_name + pos, label_len);
            ptr_to_answer += label_len;
            pos += label_len + 1;
        }
        *ptr_to_answer++ = 0;
        *(uint16_t*)ptr_to_answer = htons(dns_msg->answer[i].TYPE);
        ptr_to_answer += 2;
        *(uint16_t*)ptr_to_answer = htons(dns_msg->answer[i].CLASS);
        ptr_to_answer += 2;
        *(uint32_t*)ptr_to_answer = htonl(dns_msg->answer[i].TTL);
        ptr_to_answer += 4;
        *(uint16_t*)ptr_to_answer = htons(dns_msg->answer[i].RDLENGTH);
        ptr_to_answer += 2;
        memcpy(ptr_to_answer, dns_msg->answer[i].RDATA, dns_msg->answer[i].RDLENGTH);
        ptr_to_answer += dns_msg->answer[i].RDLENGTH;

        total_len += name_len + 1 + 2 + 2 + 4 + 2 + dns_msg->answer[i].RDLENGTH;
    }

    //设置DNS_AUTHORITY
    char *ptr_to_authority = ptr_to_answer;
    for (int i = 0; i < dns_msg->header.NSCOUNT; i++) {
        char *ptr_to_name = dns_msg->authority[i].NAME;
        int name_len = strlen(ptr_to_name);
        int pos = 0;
        while (pos < name_len) {
            int label_len = strchr(ptr_to_name + pos, '.') - (ptr_to_name + pos);
            *ptr_to_authority++ = label_len;
            memcpy(ptr_to_authority, ptr_to_name + pos, label_len);
            ptr_to_authority += label_len;
            pos += label_len + 1;
        }
        *ptr_to_authority++ = 0;
        *(uint16_t*)ptr_to_authority = htons(dns_msg->authority[i].TYPE);
        ptr_to_authority += 2;
        *(uint16_t*)ptr_to_authority = htons(dns_msg->authority[i].CLASS);
        ptr_to_authority += 2;
        *(uint32_t*)ptr_to_authority = htonl(dns_msg->authority[i].TTL);
        ptr_to_authority += 4;
        *(uint16_t*)ptr_to_authority = htons(dns_msg->authority[i].RDLENGTH);
        ptr_to_authority += 2;
        memcpy(ptr_to_authority, dns_msg->authority[i].RDATA, dns_msg->authority[i].RDLENGTH);
        ptr_to_authority += dns_msg->authority[i].RDLENGTH;

        total_len += name_len + 1 + 2 + 2 + 4 + 2 + dns_msg->authority[i].RDLENGTH;
    }

    //设置DNS_ADDITIONAL
    char *ptr_to_additional = ptr_to_authority;
    for (int i = 0; i < dns_msg->header.ARCOUNT; i++) {
        char *ptr_to_name = dns_msg->additional[i].NAME;
        int name_len = strlen(ptr_to_name);
        int pos = 0;
        while (pos < name_len) {
            int label_len = strchr(ptr_to_name + pos, '.') - (ptr_to_name + pos);
            *ptr_to_additional++ = label_len;
            memcpy(ptr_to_additional, ptr_to_name + pos, label_len);
            ptr_to_additional += label_len;
            pos += label_len + 1;
        }
        *ptr_to_additional++ = 0;
        *(uint16_t*)ptr_to_additional = htons(dns_msg->additional[i].TYPE);
        ptr_to_additional += 2;
        *(uint16_t*)ptr_to_additional = htons(dns_msg->additional[i].CLASS);
        ptr_to_additional += 2;
        *(uint32_t*)ptr_to_additional = htonl(dns_msg->additional[i].TTL);
        ptr_to_additional += 4;
        *(uint16_t*)ptr_to_additional = htons(dns_msg->additional[i].RDLENGTH);
        ptr_to_additional += 2;
        memcpy(ptr_to_additional, dns_msg->additional[i].RDATA, dns_msg->additional[i].RDLENGTH);
        ptr_to_additional += dns_msg->additional[i].RDLENGTH;

        total_len += name_len + 1 + 2 + 2 + 4 + 2 + dns_msg->additional[i].RDLENGTH;
    }
    return total_len;
}

void logDNSMessage(const struct DNS_DATA* dns_msg) {
    if (debug_mode == 0)
        return;
    else if (debug_mode == 1){
        time_t currentTime = time(NULL);
        printf("ID: 0x%x\t", dns_msg->header.ID);
        printf("Time: %s", ctime(&currentTime));
        for (int i = 0; i < dns_msg->header.QDCOUNT; i++){
            printf("DOMAIN: %s\n", dns_msg->question[i].QNAME);
        }
        for (int i = 0; i < dns_msg->header.ANCOUNT; i++){
            printf("NAME: %s\n", dns_msg->answer[i].NAME);
            printf("RDATA: ");
            for (int j = 0; j < dns_msg->answer[i].RDLENGTH; j++){
                printf("%u ", dns_msg->answer[i].RDATA[j]);
            }
        }
        return;
    }
    else if (debug_mode == 2){
        time_t currentTime = time(NULL);
        printf("ID: 0x%x\t", dns_msg->header.ID);
        printf("Time: %s", ctime(&currentTime));
        printf("FLAGS: QR %d, OPCODE %d, AA %d, TC %d, RD %d, RA %d, Z %d, RCODE %d\n", dns_msg->header.QR, dns_msg->header.OPCODE, dns_msg->header.AA, dns_msg->header.TC, dns_msg->header.RD, dns_msg->header.RA, dns_msg->header.Z, dns_msg->header.RCODE);
        printf("QDCOUNT: %d, ANCOUNT: %d, NSCOUNT: %d, ARCOUNT: %d\n", dns_msg->header.QDCOUNT, dns_msg->header.ANCOUNT, dns_msg->header.NSCOUNT, dns_msg->header.ARCOUNT);
        for (int i = 0; i < dns_msg->header.QDCOUNT; i++){
            printf("DOMAIN: %s\t TYPE: %d\t CLASS: %d\n", dns_msg->question[i].QNAME, dns_msg->question[i].QTYPE, dns_msg->question[i].QCLASS);
        }
        for (int i = 0; i < dns_msg->header.ANCOUNT; i++){
            printf("NAME: %s\t TYPE: %d\t CLASS: %d\t TTL: %d\t RDLENGTH: %d\n", dns_msg->answer[i].NAME, dns_msg->answer[i].TYPE, dns_msg->answer[i].CLASS, dns_msg->answer[i].TTL, dns_msg->answer[i].RDLENGTH);
            printf("RDATA: ");
            for (int j = 0; j < dns_msg->answer[i].RDLENGTH; j++){
                printf("%u ", dns_msg->answer[i].RDATA[j]);
            }
            printf("\n");
        }
        return;
    }
}

void cleanupDNSData(struct DNS_DATA* dns_data){
    if(dns_data->question != NULL){
        free(dns_data->question);
    }
    if(dns_data->answer != NULL){
        if(dns_data->header.ANCOUNT != 0){
            for (int i = 0; i < dns_data->header.ANCOUNT; i++){
                if(dns_data->answer[i].RDATA != NULL && dns_data->answer[i].RDLENGTH != 0){
                    free(dns_data->answer[i].RDATA);
                }
            }
            free(dns_data->answer);
        }
    }
    if(dns_data->authority != NULL){
        if(dns_data->header.NSCOUNT != 0){
            for (int i = 0; i < dns_data->header.NSCOUNT; i++){
                if(dns_data->authority[i].RDATA != NULL && dns_data->authority[i].RDLENGTH != 0){
                    free(dns_data->authority[i].RDATA);
                }
            }
            free(dns_data->authority);
        }
    }
    if(dns_data->additional != NULL){
        if(dns_data->header.ARCOUNT != 0){
            for (int i = 0; i < dns_data->header.ARCOUNT; i++){
                if(dns_data->additional[i].RDATA != NULL && dns_data->additional[i].RDLENGTH != 0){
                    free(dns_data->additional[i].RDATA);
                }
            }
            free(dns_data->additional);
        }
    }
    return;
}

// 分配一个新的forward_id，并记录映射
uint16_t allocate_forward_id(uint16_t client_id, struct sockaddr_in* client_addr) {
    static uint16_t next_forward_id = 0x8000; // 避免与客户端ID冲突
    for (int i = 0; i < MAX_ID_MAP; i++) {
        if (!id_map_table[i].valid) {
            id_map_table[i].client_id = client_id;
            id_map_table[i].forward_id = next_forward_id++;
            id_map_table[i].client_addr = *client_addr;
            id_map_table[i].timestamp = time(NULL);
            id_map_table[i].valid = 1;
            return id_map_table[i].forward_id;
        }
    }
    return client_id; // 映射表满，直接用原ID（不推荐）
}

// 查找并移除映射，返回client_id和client_addr
int find_and_remove_client_id(uint16_t forward_id, uint16_t* client_id, struct sockaddr_in* client_addr) {
    for (int i = 0; i < MAX_ID_MAP; i++) {
        if (id_map_table[i].valid && id_map_table[i].forward_id == forward_id) {
            *client_id = id_map_table[i].client_id;
            *client_addr = id_map_table[i].client_addr;
            id_map_table[i].valid = 0;
            return 1;
        }
    }
    return 0;
}

// 定期清理超时的映射
void cleanup_id_map() {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_ID_MAP; i++) {
        if (id_map_table[i].valid && now - id_map_table[i].timestamp > 30) {
            id_map_table[i].valid = 0;
        }
    }
}
