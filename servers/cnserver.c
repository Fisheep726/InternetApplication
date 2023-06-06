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
#define BACKLOG 10

struct DNS_Header{
    unsigned short id;
    unsigned short flags;
    unsigned short questions;  
    unsigned short answers;  
    unsigned short authority;
    unsigned short additional;
};

struct TCP_Header{
    unsigned short length;
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
    unsigned char rdata[512];
};

struct Translate{
    char domain[512];
    unsigned short qtype;
};

int DNS_Create_Header(struct DNS_Header *header){
    if(header == NULL)
        return -1;
    memset(header, 0x00, sizeof(struct DNS_Header));
    srandom(time(NULL));
    header -> id = random();
    header -> flags = htons(0x0100);
    header -> questions = htons(0x01);
    header -> answers = htons(0);
    header -> authority = htons(0x01);
    header -> additional = htons(0);
    return 0;
}

int TCP_Create_Header(struct TCP_Header *header){
    if(header == NULL)
        return -1;
    memset(header, 0x00, sizeof(struct DNS_Header));
    srandom(time(NULL));
    header -> length = htons(0);
    header -> id = random();
    header -> flags = htons(0x0100);
    header -> questions = htons(0x01);
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

int DNS_Create_RR(struct DNS_RR *rr, const char *domain, int ttl,
unsigned short class, unsigned short type,const char *rdata){
    memset(rr, 0x00, sizeof(struct DNS_RR));
    memset(rr -> name, 0x00, 512);
    if(rr -> name == NULL){
        return -2;
    }
    rr -> length = strlen(domain) + 1;
    rr -> class = htons(class);
    rr -> type = htons(type);
    rr -> ttl = htonl(ttl);


    const char apart[2] = ".";
    char *nameptr = rr -> name;
    char *domain_dup = strdup(domain);
    char *apartDomain = strtok(domain_dup, apart); 
    while(apartDomain != NULL){
        size_t len = strlen(apartDomain);
        *nameptr = len;
        nameptr++;
        strncpy(nameptr, apartDomain, len + 1);
        nameptr += len;
        apartDomain = strtok(NULL, apart);
    }


    char *rdataptr = rr -> rdata;
    char *rdata_dup = strdup(rdata);
    struct in_addr netip = {0};
    inet_aton(rdata_dup, &netip);
    memcpy(rdataptr, (char *)&netip.s_addr, sizeof((char *)&netip.s_addr));
    rr -> data_len = htons(0x0004);
   
    return 0;
}


int DNS_Create_Response(struct TCP_Header *header, struct DNS_Query *query, struct DNS_RR *rr, char *response, int rlen){
    if(header == NULL || query == NULL || response == NULL) return -1;
    memset(response, 0, rlen);
    memcpy(response, header, sizeof(struct TCP_Header));
    int offset = sizeof(struct TCP_Header);
    memcpy(response + offset, query -> name, query -> length + 1);
    offset += query -> length + 1;
    memcpy(response + offset, &query -> qtype, sizeof(query -> qtype));
    offset += sizeof(query -> qtype);
    memcpy(response + offset, &query -> qclass, sizeof(query -> qclass));
    offset += sizeof(query -> qclass);
    memcpy(response + offset, rr -> name, rr -> length + 1);
    offset += rr -> length + 1;
    memcpy(response + offset, &rr -> type, sizeof(rr -> type));
    offset += sizeof(rr -> type);
    memcpy(response + offset, &rr -> class, sizeof(rr -> class));
    offset += sizeof(rr -> class);
    memcpy(response + offset, &rr -> ttl, sizeof(rr -> ttl));
    offset += sizeof(rr -> ttl);
    memcpy(response + offset, &rr -> data_len, sizeof(rr -> data_len));
    offset += sizeof(rr -> data_len);
    memcpy(response + offset, rr -> rdata, 4);
    
    return offset;
}

static void DNS_Parse_Name(unsigned char *spoint, char *out, int *len){
    int flag = 0, n = 0, alen = 0;
    char *pos = out + (*len);

    while(1){
        flag = (int)spoint[0];
        if(flag == 0){
            break;
        }
        else{
            spoint++;
            memcpy(pos, spoint, flag);
            pos += flag;
            spoint += flag;

            *len += flag;
            if((int)spoint[0] != 0){
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
}

int main(){
    int tcpsock;
    struct sockaddr_in cn_server_addr, local_server_addr;
    char recvBuffer[BufferSize];
    char sendBuffer[BufferSize];
    int lsa_len = sizeof(local_server_addr);

    bzero(&cn_server_addr, sizeof(cn_server_addr));
    cn_server_addr.sin_family = AF_INET;
    cn_server_addr.sin_port = htons(PORT);
    cn_server_addr.sin_addr.s_addr = inet_addr("127.0.0.4");
    bzero(&local_server_addr, sizeof(local_server_addr));
    local_server_addr.sin_family = AF_INET;
    local_server_addr.sin_port = htons(PORT);
    local_server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);

    tcpsock = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpsock < 0){
        perror("cnserver TCP socket创建出错\n");
        exit(-1);
    }

    int on = 1;
    if(setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
        perror("cnserver TCP setsockopt出错\n ");
        exit(-1);
    }

    if(bind(tcpsock, (struct sockaddr *)&cn_server_addr, sizeof(cn_server_addr)) < 0){
        perror("cnserver TCP bind出错\n");
        exit(-1);
    }

    if(listen(tcpsock, BACKLOG) < 0){
        perror("cnserver TCP listen出错\n");
        exit(-1);
    }
    printf("cnserver server is listening...\n");

    int consock;
    if((consock = accept(tcpsock, (struct sockaddr *)&local_server_addr, &lsa_len)) < 0){
        perror("cnserver TCP accept出错\n");
        exit(-1);
    }

    if(recv(consock, recvBuffer, sizeof(recvBuffer), 0) < 0){
        perror("cnserver TCP recv 出错\n");
        exit(-1);
    }

    unsigned char *recvBufferPointer = recvBuffer;
    unsigned short qtype;
    int tempTTL = 86400;
    unsigned short tempType = 0x0001;
    unsigned short tempClass = 0x0001;
    char *apart[20];
    char *cnip = "127.0.0.4";
    char *usip = "127.0.0.5";
    char *comip = "127.0.0.6";
    char *orgip = "127.0.0.7";
    char *educnip = "127.0.0.8";
    char *govusip = "127.0.0.9";

    struct Translate request;
    bzero(&request, sizeof(struct Translate));
    int r_len = 0;
    recvBufferPointer += 14;
    DNS_Parse_Name(recvBufferPointer, request.domain, &r_len);
    recvBufferPointer += (r_len + 2);
    request.qtype = ntohs(*(unsigned short *)recvBufferPointer);
    recvBufferPointer += 2;
    r_len += 2;
    printf("request domain : %s\n", request.domain);
    printf("request qtype : %hd\n",request.qtype);

    char *domain_dup = strdup(request.domain);
    char *nextName = strtok(domain_dup, ".");
    char *tldName;
    char *t = tldName;
    while(strcmp(nextName, "cn") != 0){
        tldName = nextName;
        nextName = strtok(NULL, ".");
    }
    strcat(tldName,".cn");
    struct Translate tldrequest = {0};
    strcat(tldrequest.domain, tldName);
    tldrequest.qtype = request.qtype;
    printf("tldrequest domain : %s\n", tldrequest.domain);
    int domainlen = strlen(tldrequest.domain);
    printf("tldrequest qtype : %hd\n", tldrequest.qtype);

    char tempBuffer[BufferSize];
    char *tempBufferPointer = tempBuffer;
    struct TCP_Header header = {0};
    TCP_Create_Header(&header);
    header.flags = htons(0x8000);
    header.authority = htons(0x0001);
    header.answers = htons(0);
    char *rtype;
    if(request.qtype == 0x01){rtype = "A";}
    if(request.qtype == 0x05){rtype = "CNAME";}
    if(request.qtype == 0x0f){rtype = "MX";}
    struct DNS_Query query = {0};
    DNS_Create_Query(&query, rtype, request.domain);
    struct DNS_RR rr = {0};
    int tcplen, rrlen = 0;

    if(strcmp(tldName, "edu.cn") == 0){
        DNS_Create_RR(&rr, tldName, tempTTL, tempClass, tempType, educnip);
        tcplen = 20 + strlen(request.domain) + strlen(tldName) + 2 + 16;
        printf("cn tcplen : %d\n", tcplen);
        header.length = htons(tcplen);
        rrlen = DNS_Create_Response(&header, &query, &rr, tempBufferPointer, 512);
    }

    if(send(consock, tempBuffer, tcplen + 2, 0) < 0){
        perror("cn TCP send 出错\n");
        exit(-1);
    }
}