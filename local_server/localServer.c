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

#define AMOUNT 1500
#define BufferSize 512
#define TYPE_A        0X01
#define TYPE_CNMAE    0X05
#define TYPE_MX       0x0f

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

struct Translate{
    char domain[206];
    unsigned short qtype;
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
 unsigned short class, unsigned short type, char *rdata){
    memset(rr, 0x00, sizeof(struct DNS_RR));
    rr -> name = domain;
    rr -> class = class;
    rr -> type = type;
    rr -> ttl = ttl;
    rr -> rdata = rdata;
    rr -> data_len = strlen(rdata);
    return 0;
}

int DNS_Create_Response(struct DNS_Header *header, struct DNS_Query *query, char *response, int rlen){
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
    return offset;//返回response数据的实际长度
}

//加载本地txt文件
int cacheSearch(char *path, char *out, struct Translate *request){
    int i = 0, j = 0;
    int num = 0;
    char *temp[AMOUNT];//char型指针1500数组
    char *type;

    //将qtype转化为字母进行比对
    if(request -> qtype == htons(TYPE_A)) {type = "A";}
    if(request -> qtype == htons(TYPE_MX)) {type = "MX";}
    if(request -> qtype == htons(TYPE_CNMAE)) {type = "CNAME";}

    FILE *fp = fopen(path, "ab+");//ab+ ：打开一个二进制文件，允许读或在文件末追加数据
    if(!fp){
        printf("Open file failed\n");
        exit(-1);
    }
    char *reac;
    //把每一行分开的操作
    while(i < AMOUNT - 1){
        temp[i] = (char *)malloc(sizeof(char)*200);//*200可去除
        if(fgets(temp[i], AMOUNT, fp) == NULL) break;//如果错误或者读到结束符，就返回NULL
        else{
        reac = strchr(temp[i], '\n');//strchr对单个字符进行查找
        if(reac) *reac = '\0';
        printf("%s\n", temp[i]);
        }
        i++;
    } 
    if(i == AMOUNT - 1) printf("The DNS record memory is full.\n");

    //把temp[i]切割成 IP 和 domain
    for(j < i; j++;){
        char *cacheDomain = strtok(temp[j], " ");
        char *cacheTTL = strtok(NULL, " ");
        char *cacheClass = strtok(NULL, " ");
        char *cacheType = strtok(NULL, " ");
        char *cacheRdata = strtok(NULL, " ");
        //如果Domain和Type匹对成功，返回Rdata
        if(strcmp(cacheDomain, request -> domain) == 0 || strcmp(cacheType, type) == 0){
            printf("same request exsit in cache\n");
            unsigned short tempClass;
            if(strcmp(cacheClass, "IN") == 0){tempClass = 0x01;}
            unsigned short tempType;
            if(strcmp(cacheType, "A") == 0){tempType = 0x01;}
            if(strcmp(cacheType, "MX") == 0){tempType = 0x0f;}
            if(strcmp(cacheType, "CNAME") == 0){tempType = 0x05;}
            //生成response
            struct DNS_Header header = {0};
            DNS_Create_Header(&header);
            struct DNS_Query query = {0};
            DNS_Create_Query(&query, type, domain);
            struct DNS_RR rr = {0};
            DNS_Create_RR(&rr, cacheDomain, atoi(cacheTTL), )
            DNS_Create_Response(&header, &query, out, 512);
            return 0;
        }
        else{
            printf("this is a new request\n");
            return -1;
        }
    } 
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


int main(){
    //UDP
    //server端套接字文件描述符
    int udpsock;
    struct sockaddr_in server_addr;//本机地址
    struct sockaddr_in client_addr;//客户端地址
    size_t server_addr_len = sizeof(struct sockaddr_in);
    size_t client_addr_len = sizeof(struct sockaddr_in);

    udpsock = socket(AF_INET, SOCK_DGRAM, 0);
    if(udpsock < 0){
        perror("local UDP socket创建出错\n");
        exit(1);
    }
    
    //发送缓冲区和接收缓冲区
    char sendtoBuffer[BufferSize];
    char recvfromBuffer[BufferSize];
    char *sendtoBufferPointer = sendtoBuffer;
    char *recvfromBufferPointer = recvfromBuffer;
    //初始化buffer
    memset(sendtoBuffer, 0, BufferSize);
    memset(recvfromBuffer, 0, BufferSize);

    //  <和client的UDP连接>
    //初始化server端套接字
    bzero(&server_addr,sizeof(server_addr));
    //用htons和htonl将端口和地址转成网络字节序
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(LOCAL_SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);//点分十进制地址转化为网络所用的二进制数，替换inter_pton

    //对于bind， accept之类的函数， 里面的套接字参数都是需要强制转化成（struct sockaddr *)
    //绑定服务器IP端口
    if(bind(udpsock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        perror("local UDP bind出错\n");
        exit(-1);
    }
    printf("Server started. Waiting for data...\n");

    //接收request
    if(recvfrom(udpsock, recvfromBuffer, sizeof(recvfromBuffer), 0, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_len) == -1){
        perror("local UDP recvfrom出错\n");
        exit(-1);
    }

    struct Translate request;
    bzero(&request, sizeof(struct Translate));
    int r_len = 0;
    //Header部分定长为24字节,跳过即可
    //request[12]开始是query name 的第一个数字
    recvfromBufferPointer += 12;
    DNS_Parse_Name(request.domain, recvfromBufferPointer, &r_len);
    recvfromBufferPointer += (r_len + 2);
    request.qtype = ntohs(*(unsigned short *)recvfromBufferPointer);
    recvfromBufferPointer += 2;
    r_len += 2;
    if(cacheSearch("E:\\Desktop\\demo.txt\n",sendtoBufferPointer, &request) == 0){
        //cache中存在,返回response
        sendto(udpsock, sendtoBuffer, strlen(sendtoBuffer), 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if(sendto < 0){
            perror("local UDP sendto 出错\n");
            exit(-1);
        }
        // close(udpsock);
    }

    //TCP
    int tcpsock;
    struct sockaddr_in root_server_addr, local_server_addr;
    char recvBuffer[BufferSize];
    char sendBuffer[BufferSize];
    char *sendBufferPointer = sendBuffer;

    bzero(&local_server_addr, sizeof(local_server_addr));
    local_server_addr.sin_family = AF_INET;
    local_server_addr.sin_port = htons(LOCAL_SERVER_PORT_TEMP);
    local_server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
    bzero(&root_server_addr, sizeof(root_server_addr));
    root_server_addr.sin_family = AF_INET;
    root_server_addr.sin_port = htons(ROOT_SERVER_PORT);
    root_server_addr.sin_addr.s_addr = inet_addr(ROOT_SERVER_IP);

    tcpsock = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpsock < 0){
        perror("local TCP socket创建出错\n");
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

    //给sendBuffer赋值
    memcpy(sendBufferPointer, recvfromBufferPointer, BufferSize);

     //传输信息
    if(send(tcpsock, sendBuffer, strlen(sendBuffer), 0) < 0){
        perror("local TCP send 出错\n");
        exit(-1);
    }

    if(recv(tcpsock, recvBuffer, sizeof(recvBuffer), 0) < 0){
        perror("local TCP recv 出错\n");
        exit(-1);
    }
}