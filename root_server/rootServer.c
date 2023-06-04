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
// #include <ip_port.h>
#define CLIENT_PORT 53
#define CLIENT_IP "127.0.0.1"
#define LOCAL_SERVER_PORT 53
#define LOCAL_SERVER_IP "127.0.0.2"
#define ROOT_SERVER_PORT 53
#define LOCAL_SERVER_PORT_TEMP 8080
#define ROOT_SERVER_IP "127.0.0.3"
#define TLD_SERVER_PORT 53
#define TLD_SERVER_IP "127.0.0.4"

#define BufferSize 512
#define BACKLOG 10//最大同时请求连接数

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
    header -> flags = htons(0x0100);//query_flag = 0x0100
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
        *qname = len;//长度的ASCII码
        qname++;
        strncpy(qname, token, len +1);
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
    rr -> data_len = strlen(rdata) + 1;

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

    char *rdata_dup = strdup(rdata);
    // char *rdataptr = rr -> rdata;
    char hex[3];
    char *apartRdata = strtok(rdata_dup, apart);
    while(apartRdata != NULL){
        int num = atoi(apartRdata);
        sprintf(hex, "%02X", num);
        strcat(rr -> rdata,hex);
        apartRdata = strtok(NULL, apart);
    }
    printf("root response rdata : %s", rr -> rdata);
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
    // memcpy(response + offset, &rr -> pre, sizeof(rr -> pre));
    // offset += sizeof(rr -> pre);
    memcpy(response + offset, rr -> radata, rr -> data_len + 1);
    offset += rr -> data_len + 1;
    return offset;//返回response数据的实际长度
}

static void DNS_Parse_Name(unsigned char *spoint, char *out, int *len){
    int flag = 0, n = 0, alen = 0;
    //pos指向的内存用于储存解析得到的结果
    char *pos = out + (*len);//传入的 *len = 0

    //开始解析name的报文
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

//判断.com .org .cn .us 并返回对应服务器IP
//建立和local server 的TCP连接
int main(){
    int tcpsock;
    struct sockaddr_in root_server_addr, local_server_addr;
    char recvBuffer[BufferSize];
    char sendBuffer[BufferSize];
    int lsa_len = sizeof(local_server_addr);

    bzero(&root_server_addr, sizeof(root_server_addr));
    root_server_addr.sin_family = AF_INET;
    root_server_addr.sin_port = htons(ROOT_SERVER_PORT);
    root_server_addr.sin_addr.s_addr = inet_addr(ROOT_SERVER_IP);
    bzero(&local_server_addr, sizeof(local_server_addr));
    local_server_addr.sin_family = AF_INET;
    local_server_addr.sin_port = htons(LOCAL_SERVER_PORT_TEMP);
    local_server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);

    tcpsock = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpsock < 0){
        perror("root TCP socket创建出错\n");
        exit(-1);
    }

    if(bind(tcpsock, (struct sockaddr *)&root_server_addr), sizeof(root_server_addr) < 0){
        perror("root TCP bind出错\n");
        exit(-1);
    }

    if(listen(tcpsock, BACKLOG) < 0){
        perror("root TCP listen出错\n");
        exit(-1);
    }
    printf("root server is listening...\n");

    if(accept(tcpsock, (struct sockaddr *)&local_server_addr, &lsa_len) < 0){
        perror("root TCP accept出错\n");
        exit(-1);
    }

    if(recv(tcpsock, recvBuffer, sizeof(recvBuffer), 0) < 0){
        perror("local TCP recv 出错\n");
        exit(-1);
    }

    //解析顶级域名
    char *recvBufferPointer = recvBuffer;
    char name[512];
    unsigned short qtype;
    int d_len = 0;
    int tempTTL = 86400;
    unsigned short tempType = 0x01;
    unsigned short tempClass = 0x01;
    char *apart[20]
    char *rootName;
    char *comip = "127.0.0.5";

    //截取domain，跳过Header
    recvBufferPointer += 12;
    DNS_Parse_Name(&name, recvBufferPointer, &d_len);
    recvBufferPointer += d_len;
    apart[0] = strtok(name, ".");
    //截取顶级域名
    for(int t = 1; t<10; t++){
        apart[t] = strtok(NULL, ".");
        if(apart[t] == NULL){
            rootName = strtok(apart[t-1], " ");
        }
    }
    qtype = ntohs(*(unsigned short *)recvBufferPointer);
    recvBufferPointer += 2;

    //生成response
    struct DNS_Header header = {0};
    DNS_Create_Header(&header);
    header.flags = htons(0x8000);
    struct DNS_Query query = {0};
    DNS_Create_Query(&query, 0, name);
    query.qtype = htons(qtype);
    struct DNS_RR rr = {0};

    //加入判断，决定返回的IP地址
    if(strcmp(rootName, "com") == 0){
        //返回com的TLD服务器IP
        DNS_Create_RR(&rr, rootName, tempTTL, tempClass, tempType, comip);
        DNS_Create_Response(&header, &query, &sendBuffer, 512);

    }

    if(strcmp(rootName, "org" == 0){
        //返回org的TLD服务器IP
        
    })

    if(strcmp(rootName, "cn") == 0){
        //返回cn的TLD服务器IP
    }

    if(strcmp(rootName, "us") == 0){
        //返回us的TLD服务器IP
    }

    if(send(tcpsock, sendBuffer, strlen(sendBuffer), 0) < 0){
        perror("local TCP send 出错\n");
        exit(-1);
    }
}