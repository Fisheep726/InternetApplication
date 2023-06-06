#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#define PORT 53
#define CLIENT_IP "127.0.0.1"
#define LOCAL_SERVER_IP "127.0.0.2"
#define ROOT_SERVER_IP "127.0.0.3"
#define AMOUNT 1500
#define BufferSize 512
#define TYPE_A        0X0001
#define TYPE_CNMAE    0X0005
#define TYPE_MX       0x000f


struct DNS_Header{
    unsigned short id; 
    unsigned short flags;

    unsigned short questions;
    unsigned short answers;

    unsigned short authority;
    unsigned short additional;
};

struct DNS_Query{
    int length;
    unsigned short qtype;
    unsigned short qclass;
    unsigned char name[512];
};

struct DNS_RR{
    int length;
    unsigned char name[512];
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned short pre;
    unsigned char rdata[512];
};

int DNS_Create_Header(struct DNS_Header *header){
    if(header == NULL)
        return -1;
    memset(header, 0x00, sizeof(struct DNS_Header));
    srandom(time(NULL));
    header -> id = random();
    header -> flags = htons(0x0100);
    header -> questions = htons(0x0001);
    header -> answers = htons(0);
    header -> authority = htons(0);
    header -> additional = htons(0);
    return 0;
}

int DNS_Create_Query(struct DNS_Query *query, const char *type, const char *hostname){
    if(query == NULL || hostname == NULL)
        return -1;
    memset(query, 0x00, sizeof(struct DNS_Query));
    memset(query->name,0x00,512);
    if(query -> name ==NULL){
        return -2;
    }
    query -> length = strlen(hostname) + 1;
    unsigned short qtype;
    if(strcmp(type,"A") == 0)query -> qtype = htons(TYPE_A);
    if(strcmp(type,"MX") == 0)query -> qtype = htons(TYPE_MX);
    if(strcmp(type,"CNAME") == 0)query -> qtype = htons(TYPE_CNMAE);
    query -> qclass = htons(0x0001);

    const char apart[2] = ".";
    char *qname = query -> name;
    char *hostname_dup = strdup(hostname);
    char *token = strtok(hostname_dup, apart);

    while(token != NULL){
        size_t len = strlen(token);
        *qname = len;
        qname++;
        strncpy(qname, token, len +1);
        qname += len;
        token = strtok(NULL, apart);
    } 
    free(hostname_dup);
    return 0;
}

int DNS_Create_Requestion(struct DNS_Header *header, struct DNS_Query *query, char *request, int rlen){
    if(header == NULL || query == NULL || request == NULL)
        return -1;

    memset(request, 0, rlen);
    memcpy(request, header, sizeof(struct DNS_Header));
    int offset = sizeof(struct DNS_Header);
    memcpy(request + offset, query -> name, query -> length + 1);
    offset += query -> length + 1;
    memcpy(request + offset, &query -> qtype, sizeof(query -> qtype));
    offset += sizeof(query -> qtype);
    memcpy(request + offset, &query -> qclass, sizeof(query -> qclass));
    offset += sizeof(query -> qclass);
    return offset;
}

static int is_pointer(int in){
    return((in & 0xc0) == 0xc0);
}
static void DNS_Parse_Name(unsigned char* spoint, unsigned char *ptr, char *out, int *len){
    int flag = 0, n = 0, alen = 0;
    char *pos = out + (*len);

    while(1){
        flag = (int)ptr[0];
        if(flag == 0){
            break;
        }

        if(is_pointer(flag)){
            n = (int)ptr[1];
            ptr = spoint + n;
            DNS_Parse_Name(spoint, ptr, out, len);
            break;
        }
        else{
            ptr++;
            memcpy(pos, ptr, flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if((int)ptr[0] != 0){
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
}

static int DNS_Parse_Response(char *response){
    if(response == NULL){
        printf("No response!\n");
        return -1;
    }
    unsigned char *ptr = response;
    struct DNS_Header header = {0};
    header.id = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.flags = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.questions = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.answers = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.authority = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.additional = ntohs(*(unsigned short *)ptr);
    ptr += 2;

    struct DNS_Query *query = calloc(header.questions, sizeof(struct DNS_Query));
    for(int i = 0; i < header.questions; i++){
        DNS_Parse_Name(response, ptr, query[i].name, &query[i].length);
        printf("query name: %s\n", query[i].name);
        ptr += (query[i].length + 2);
        query[i].qtype = ntohs(*(unsigned short *)ptr);
        printf("query type: %d\n", query[i].qtype);
        ptr += 2;
        query[i].qclass = ntohs(*(unsigned short *)ptr);
        ptr += 2;
    }

    char ip[20],netip[4];
    struct DNS_RR *rr = calloc(header.answers, sizeof(struct DNS_RR));
    for(int i = 0; i < header.answers; i++){
        rr[i].length = 0;
        DNS_Parse_Name(response, ptr, rr[i].name, &rr[i].length);
        printf("answer%d name: %s\n", i, rr[i].name);
        printf("rr.length is : %d\n", rr[i].length);
        ptr += (rr[i].length + 2);

        rr[i].type = ntohs(*(unsigned short *)ptr);
        printf("answer type: %d\n", rr[i].type);
        ptr += 2;
        rr[i].class = ntohs(*(unsigned short *)ptr);
        ptr += 2;
        rr[i].ttl = ntohs(*(unsigned short *)ptr);
        ptr += 4;
        rr[i].data_len = ntohs(*(unsigned short *)ptr);
        ptr += 2;

        rr[i].length = 0;

        if(rr[i].type == TYPE_CNMAE){
            DNS_Parse_Name(response, ptr, rr[i].rdata, &rr[i].length);
            ptr += rr[i].data_len;
            printf("%s has a cname of %s \n", rr[i].name, rr[i].rdata);
        }
        else if(rr[i].type == TYPE_A){
            bzero(ip,sizeof(ip));
            memcpy(netip, ptr, 4);
            DNS_Parse_Name(response, ptr, rr[i].rdata, &rr[i].length);
            ptr += rr[i].data_len;
            inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
            printf("%s has an address of %s \n", rr[i].name, ip);
        }
        else if(rr[i].type == TYPE_MX){
            ptr += 2;
            DNS_Parse_Name(response, ptr, rr[i].rdata, &rr[i].length);
            ptr += (rr[i].data_len - 2);
            printf("%s has a Mail eXchange name of %s\n", rr[i].name, rr[i].rdata);
        }
    }
    return 0;
}

int DNS_Client_Commit(const char *type, const char *domain){
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        return -1;
    }
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    struct DNS_Header header = {0};
    DNS_Create_Header(&header);
    struct DNS_Query query = {0};
    DNS_Create_Query(&query, type, domain);
    char request[512] = {0};
    int len = DNS_Create_Requestion(&header, &query, request, 512);
    int slen = sendto(sockfd, request, len, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));
    char response[512] = {0};
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);
    int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr, (socklen_t *)&addr_len);
    DNS_Parse_Response(response);

    return n;
}

int main(int argc, char *argv[])
{
    if(argc < 3) return -1;
    DNS_Client_Commit(argv[1], argv[2]);
    return 0;
}