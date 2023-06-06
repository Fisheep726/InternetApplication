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

//PORT AND IP
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
    unsigned short pre;
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
    header -> authority = htons(0);
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

    if(type == 0x000f){
        rr -> pre = htons(0x0005);
        char *rdataptr = rr -> rdata;
        char *rdata_dup = strdup(rdata);
        char *apartRdata = strtok(rdata_dup, apart); 
        while(apartRdata != NULL){
        size_t len = strlen(apartRdata);
        *rdataptr = len;
        rdataptr++;
        strncpy(rdataptr, apartRdata, len + 1);
        rdataptr += len;
        apartRdata = strtok(NULL, apart);
        int data_len = strlen(rdata) + 4;
        rr -> data_len = htons(data_len);
        }
    }

    if(type == 0x0005){
        char *rdataptr = rr -> rdata;
        char *rdata_dup = strdup(rdata);
        char *apartRdata = strtok(rdata_dup, apart); 
        while(apartRdata != NULL){
        size_t len = strlen(apartRdata);
        *rdataptr = len;
        rdataptr++;
        strncpy(rdataptr, apartRdata, len + 1);
        rdataptr += len;
        apartRdata = strtok(NULL, apart);
        int data_len = strlen(rdata) + 2;
        rr -> data_len = htons(data_len);
        }
    }

    if(type == 0x0001){
        char *rdataptr = rr -> rdata;
        char *rdata_dup = strdup(rdata);
        char *apartRdata = strtok(rdata_dup, apart); 
        while(apartRdata != NULL){
        int num = atoi(apartRdata);
        char *hex = (char *)malloc(sizeof(char) *9);
        sprintf(hex, "%02x", num);
        strncpy(rdataptr, hex, 2);
        rdataptr += 2;
        apartRdata = strtok(NULL, apart);
        }
        uint32_t host_num = strtoul(rr -> rdata, NULL, 16);
        uint32_t net_num = htonl(host_num);
        memcpy(rr -> rdata, &net_num, sizeof(net_num));
        int datalen = strlen(rr -> rdata);
        rr -> data_len = htons(4);
        int lenlen = sizeof(rr -> data_len);
    }


    return 0;
}

int DNS_Create_Response(struct DNS_Header *header, struct DNS_Query *query, struct DNS_RR *rr, char *response, int rlen){
    if(header == NULL || query == NULL || response == NULL) return -1;
    memset(response, 0, rlen);
    memcpy(response, header, sizeof(struct DNS_Header));
    int offset = sizeof(struct DNS_Header);
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
    memcpy(response + offset, rr -> rdata, strlen(rr -> rdata));
    offset += sizeof(rr -> rdata);
    
    return offset;
}

int TCP_Create_Requestion(struct TCP_Header *header, struct DNS_Query *query, char *request, int rlen){
    if(header == NULL || query == NULL || request == NULL)
        return -1;

    memset(request, 0, rlen);
    memcpy(request, header, sizeof(struct TCP_Header));
    int offset = sizeof(struct TCP_Header);
    memcpy(request + offset, query -> name, query -> length + 1);
    offset += query -> length + 1;
    memcpy(request + offset, &query -> qtype, sizeof(query -> qtype));
    offset += sizeof(query -> qtype);
    memcpy(request + offset, &query -> qclass, sizeof(query -> qclass));
    offset += sizeof(query -> qclass);
    return offset;
}

int cacheSearch(char *path, char *out, struct Translate *request){
    int i = 0, j = 0;
    int num = 0;
    char *temp[AMOUNT];
    char *type;

    if(request -> qtype == htons(TYPE_A)) {type = "A";}
    if(request -> qtype == htons(TYPE_MX)) {type = "MX";}
    if(request -> qtype == htons(TYPE_CNMAE)) {type = "CNAME";}

    FILE *fp = fopen(path, "ab+");
    if(!fp){
        printf("Open file failed\n");
        exit(-1);
    }
    char *reac;

    while(i < AMOUNT - 1){
        temp[i] = (char *)malloc(sizeof(char)*200);
        if(fgets(temp[i], AMOUNT, fp) == NULL) break;
        else{
        reac = strchr(temp[i], '\n');
        if(reac) *reac = '\0';
        }
        i++;
    } 
    if(i == AMOUNT - 1) printf("The DNS record memory is full.\n");
    printf("first reader is ok\n");

    while(j < i){
        char *cacheDomain = strtok(temp[j], " ");
        char *cacheTTL = strtok(NULL, " ");
        char *cacheClass = strtok(NULL, " ");
        char *cacheType = strtok(NULL, " ");
        char *cacheRdata = strtok(NULL, " ");
        unsigned short tempClass;
        unsigned short tempType;
        if(strcmp(cacheClass, "IN") == 0){tempClass = 0x0001;}
        if(strcmp(cacheType, "A") == 0){tempType = 0x0001;}
        if(strcmp(cacheType, "MX") == 0){tempType = 0x000f;}
        if(strcmp(cacheType, "CNAME") == 0){tempType = 0x0005;}
        printf("second read is ok\n");
        
        if(strcmp(cacheDomain, request -> domain) == 0 && tempType == request -> qtype){
            printf("same request exsit in cache\n");
            struct DNS_Header header = {0};
            DNS_Create_Header(&header);
            header.flags = htons(0x8000);
            header.answers = htons(0x0001);
            struct DNS_Query query = {0};
            DNS_Create_Query(&query, cacheType, request -> domain);
            struct DNS_RR rr = {0};
            DNS_Create_RR(&rr, cacheDomain, atoi(cacheTTL), tempClass, tempType, cacheRdata);
            int rlen = DNS_Create_Response(&header, &query, &rr, out, 512);
            return rlen;
        }
        else{j++;}
    }
    printf("this is a new request\n");
    return -1;
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

static int TCP_Parse_Response(char *response, char *nextptr){
    if(response == NULL){
        printf("No response!\n");
        return -1;
    }
    unsigned char *ptr = response;
    struct TCP_Header header = {0};
    header.length = ntohs(*(unsigned short *)ptr);
    ptr += 2;
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
        DNS_Parse_Name(ptr, query[i].name, &query[i].length);
        ptr += (query[i].length + 2);

        query[i].qtype = ntohs(*(unsigned short *)ptr);
        if(query[i].qtype != 0){printf("query type: %d\n", query[i].qtype);}
        if(query[i].qtype != 0){printf("query name: %s\n", query[i].name);}
        ptr += 2;
        query[i].qclass = ntohs(*(unsigned short *)ptr);
        ptr += 2;
    }

    char ip[20],netip[4];
    struct DNS_RR *rr = calloc(header.answers, sizeof(struct DNS_RR));
    if(header.answers > 0){
        for(int i = 0; i < header.answers; i++){
            rr[i].length = 0;
            DNS_Parse_Name(ptr, rr[i].name, &rr[i].length);
            printf("answer%d name: %s\n", i, rr[i].name);
            ptr += rr[i].length + 2;

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
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);
                ptr += rr[i].data_len;
                printf("%s has a cname of %s \n", rr[i].name, rr[i].rdata);
            }
            else if(rr[i].type == TYPE_A){
                bzero(ip,sizeof(ip));
                memcpy(netip, ptr, 4);
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);
                ptr += rr[i].data_len;
                inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
                printf("%s has an address of %s \n", rr[i].name, ip);
                memcpy(nextptr, ip , sizeof(ip));
            }
            else if(rr[i].type == TYPE_MX){
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);
                ptr += (rr[i].data_len - 2);
                printf("%s has a Mail eXchange name of %s\n", rr[i].name, rr[i].rdata);
            }
        }
    }

    if(header.answers == 0){
        for(int i = 0; i < header.authority; i++){
            rr[i].length = 0;
            DNS_Parse_Name(ptr, rr[i].name, &rr[i].length);
            printf("answer%d name: %s\n", i, rr[i].name);
            ptr += rr[i].length + 2;

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
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);
                ptr += rr[i].data_len;
                printf("%s has a cname of %s \n", rr[i].name, rr[i].rdata);
            }
            else if(rr[i].type == TYPE_A){
                bzero(ip,sizeof(ip));
                memcpy(netip, ptr, 4);
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);
                ptr += rr[i].data_len;
                inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
                printf("%s has an address of %s \n", rr[i].name, ip);
                memcpy(nextptr, ip , sizeof(ip));
            }
            else if(rr[i].type == TYPE_MX){
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);
                ptr += (rr[i].data_len - 2);
                printf("%s has a Mail eXchange name of %s\n", rr[i].name, rr[i].rdata);
            }
        }
    }
    if(header.authority > 0){
        return 1;
    }
    return 0;
}


int main(){
    int udpsock;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    size_t server_addr_len = sizeof(struct sockaddr_in);
    size_t client_addr_len = sizeof(struct sockaddr_in);

    udpsock = socket(AF_INET, SOCK_DGRAM, 0);
    if(udpsock < 0){
        perror("local UDP socket创建出错\n");
        exit(1);
    }
    
    char sendtoBuffer[BufferSize];
    char recvfromBuffer[BufferSize];
    char *sendtoBufferPointer = sendtoBuffer;
    unsigned char *recvfromBufferPointer = recvfromBuffer;

    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);

    if(bind(udpsock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        perror("local UDP bind出错\n");
        exit(-1);
    }
    printf("root server started. Waiting for data...\n");

    if(recvfrom(udpsock, recvfromBuffer, sizeof(recvfromBuffer), 0, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_len) == -1){
        perror("local UDP recvfrom出错\n");
        exit(-1);
    }

    struct Translate request;
    bzero(&request, sizeof(struct Translate));
    int r_len = 0;
    recvfromBufferPointer += 12;
    DNS_Parse_Name(recvfromBufferPointer, request.domain, &r_len);
    recvfromBufferPointer += (r_len + 2);
    request.qtype = ntohs(*(unsigned short *)recvfromBufferPointer);
    recvfromBufferPointer += 2;
    r_len += 16;
   
    int rrlen = cacheSearch("//home//fisheep//demo.txt",sendtoBufferPointer, &request);
    if(rrlen > 0){
        printf("cacheSerch successful!\n");
        sendto(udpsock, sendtoBuffer, rrlen, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if(sendto < 0){
            perror("local UDP sendto 出错\n");
            exit(-1);
        }
        close(udpsock);
        return 0;
    }

    int tcpsock;
    struct sockaddr_in root_server_addr, local_server_addr;
    char recvBuffer[BufferSize];
    char sendBuffer[BufferSize];
    char *sendBufferPointer = sendBuffer;

    bzero(&local_server_addr, sizeof(local_server_addr));
    local_server_addr.sin_family = AF_INET;
    local_server_addr.sin_port = htons(PORT);
    local_server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    bzero(&root_server_addr, sizeof(root_server_addr));
    root_server_addr.sin_family = AF_INET;
    root_server_addr.sin_port = htons(PORT);
    root_server_addr.sin_addr.s_addr = inet_addr(ROOT_SERVER_IP);

    tcpsock = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpsock < 0){
        perror("local TCP socket创建出错\n");
        exit(-1);
    }

    int on = 1;
    if(setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
        perror("root TCP setsockopt ADDR出错\n ");
        exit(-1);
    }

    if(setsockopt(tcpsock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0){
        perror("root TCP setsockopt PORT出错\n ");
        exit(-1);
    }

    if(bind(tcpsock, (struct sockaddr *)&local_server_addr, sizeof(local_server_addr)) < 0){
        perror("local TCP bind出错\n");
        exit(-1);
    }

    if(connect(tcpsock, (struct sockaddr *)&root_server_addr, sizeof(root_server_addr)) < 0){
        perror("local TCP connect出错\n");
        exit(-1);
    }

    struct TCP_Header header = {0};
    TCP_Create_Header(&header);
    header.flags = htons(0x8000);
    char *rtype;
    if(request.qtype == 0x01){rtype = "A";}
    if(request.qtype == 0x05){rtype = "CNAME";}
    if(request.qtype == 0x0f){rtype = "MX";}
    struct DNS_Query query = {0};
    DNS_Create_Query(&query, rtype, request.domain);
    char TCPrequest[512];
    char *TCPrequestPointer = TCPrequest;
    int tcplen = 18 + strlen(request.domain) + 2;
    header.length = htons(tcplen);
    int totallen = TCP_Create_Requestion(&header, &query, TCPrequestPointer, tcplen);

    if(send(tcpsock, &TCPrequest, tcplen + 2, 0) < 0){
        perror("local TCP send 出错\n");
        exit(-1);
    }

    if(recv(tcpsock, recvBuffer, sizeof(recvBuffer), 0) < 0){
        perror("local TCP recv 出错\n");
        exit(-1);
    }
    char nextip[20];
    char *nextptr = nextip;
    int next = TCP_Parse_Response(recvBuffer,nextptr);

    if(next > 0){
        printf("nextip : %s\n", nextip);
        close(tcpsock);
    }

    int tcpsock1;
    struct sockaddr_in tld_server_addr, local_server_addr1;
    char sendBuffer1[BufferSize];
    char recvBuffer1[BufferSize];
    char *sendBuffer1Pointer = sendBuffer1;
    char *recvBuffer1Pointer = recvBuffer1;

    bzero(&local_server_addr1, sizeof(local_server_addr1));
    local_server_addr1.sin_family = AF_INET;
    local_server_addr1.sin_port = htons(PORT);
    local_server_addr1.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    bzero(&tld_server_addr, sizeof(tld_server_addr));
    tld_server_addr.sin_family = AF_INET;
    tld_server_addr.sin_port = htons(PORT);
    tld_server_addr.sin_addr.s_addr = inet_addr(nextip);

    tcpsock1 = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpsock1 < 0){
        perror("local TCP1 socket创建出错\n");
        exit(-1);
    }

    if(setsockopt(tcpsock1, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
        perror("root TCP setsockopt ADDR出错\n ");
        exit(-1);
    }

    if(setsockopt(tcpsock1, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0){
        perror("root TCP setsockopt PORT出错\n ");
        exit(-1);
    }


    if(bind(tcpsock1, (struct sockaddr *)&local_server_addr1, sizeof(local_server_addr1)) < 0){
        perror("local TCP1 bind出错\n");
        exit(-1);
    }

    if(connect(tcpsock1, (struct sockaddr *)&tld_server_addr, sizeof(tld_server_addr)) < 0){
        perror("local TCP1 connect出错\n");
        exit(-1);
    }

    if(send(tcpsock1, &TCPrequest, tcplen + 2, 0) < 0){
        perror("local TCP1 send 出错\n");
        exit(-1);
    }

    if(recv(tcpsock1, recvBuffer1, sizeof(recvBuffer1), 0) < 0){
        perror("local TCP recv 出错\n");
        exit(-1);
    }

    next = TCP_Parse_Response(recvBuffer1, nextptr);
    if(next == 0){
        int recvlen = ntohs(*(unsigned short *)recvBuffer1Pointer);
        recvBuffer1Pointer += 2;
        memcpy(sendtoBufferPointer,recvBuffer1Pointer,510);
        sendto(udpsock, sendtoBuffer, recvlen, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if(sendto < 0){
            perror("local UDP sendto 出错\n");
            exit(-1);
        }
        close(udpsock);
    }

    if(next > 0){
        printf("nextip : %s\n", nextip);
        close(tcpsock1);
    }

    int tcpsock2;
    struct sockaddr_in sec_server_addr, local_server_addr2;
    char sendBuffer2[BufferSize];
    char recvBuffer2[BufferSize];
    char *sendBuffer2Pointer = sendBuffer2;
    char *recvBuffer2Pointer = recvBuffer2;

    bzero(&local_server_addr2, sizeof(local_server_addr2));
    local_server_addr2.sin_family = AF_INET;
    local_server_addr2.sin_port = htons(PORT);
    local_server_addr2.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    bzero(&sec_server_addr, sizeof(sec_server_addr));
    sec_server_addr.sin_family = AF_INET;
    sec_server_addr.sin_port = htons(PORT);
    sec_server_addr.sin_addr.s_addr = inet_addr(nextip);

    tcpsock2 = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpsock2 < 0){
        perror("local TCP2 socket创建出错\n");
        exit(-1);
    }

    if(setsockopt(tcpsock2, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
        perror("root TCP2 setsockopt ADDR出错\n ");
        exit(-1);
    }

    if(setsockopt(tcpsock2, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0){
        perror("root TCP2 setsockopt PORT出错\n ");
        exit(-1);
    }


    if(bind(tcpsock2, (struct sockaddr *)&local_server_addr2, sizeof(local_server_addr2)) < 0){
        perror("local TCP2 bind出错\n");
        exit(-1);
    }

    if(connect(tcpsock2, (struct sockaddr *)&sec_server_addr, sizeof(sec_server_addr)) < 0){
        perror("local TCP2 connect出错\n");
        exit(-1);
    }

    if(send(tcpsock2, &TCPrequest, tcplen + 2, 0) < 0){
        perror("local TCP2 send 出错\n");
        exit(-1);
    }

    if(recv(tcpsock1, recvBuffer2, sizeof(recvBuffer2), 0) < 0){
        perror("local TCP2 recv 出错\n");
        exit(-1);
    }

    next = TCP_Parse_Response(recvBuffer2, nextptr);
    if(next == 0){
        int recvlen = ntohs(*(unsigned short *)recvBuffer2Pointer);
        printf("recvlen : %d\n",recvlen);
        recvBuffer2Pointer += 2;
        memcpy(sendtoBufferPointer,recvBuffer2Pointer,510);
        printf("copy successful\n");
        sendto(udpsock, sendtoBuffer, recvlen, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if(sendto < 0){
            perror("local UDP sendto 出错\n");
            exit(-1);
        }
        close(udpsock);
    }

    return 0;
}