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

#define LOCAL_SERVER_PORT 53;
#define LOCAL_SERVER_IP "127.0.0.2";
#define BACKLOG 10;//最大同时请求连接数
#define AMOUNT 1500;

struct DNS_Header{
    unsigned short id;
    unsigned short flags;
    unsigned short questions;  
    unsigned short answers;  
    unsigned short authority;
    unsigned short additional;
};

struct Translate{
    char *ip[20];
    unsigned short qtype;
};

struct IDchange{
    unsigned short oldID;//原有ID
    bool done;           //标记是否完成解析
    sockaddr_in client;  //请求者套接字地址
}

//当authority的数量为0表示结束
int isEnd(struct DNS_Header *header){
    if(header -> authority != 0) return 0;
    return 1;
}

//加载本地txt文件
int cacheSearch(char *path, struct Translate *request){
    struct Translate DNSTable[AMOUNT];
    int i = 0, j = 0;
    int num = 0;
    char *temp[AMOUNT];//char型指针1500数组
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
    for(j < i; j++){
        char *cacheType = strtok(temp[j], ",");
        char *cacheDomain = strtok(temp[j],",");
        DNSTable -> qtype = cacheType;
        DNSTable -> domain = cacheDomain;
        //如果域名匹对成功，就将对应的type读入
        if(strcmp(DNSTable -> domain, request -> domain) == 0){
            if(strcmp(DNSTable -> qtype, request -> qtype) == 0)
            printf("same request exsit in cache\n");
            return 0;
        }
        else{
            printf("this is a new request\n");
            return -1;
        }
    } 
}

static void DNS_Parse_Name(unsigned char *sendBufferPointer, char *out, int *len){
    int flag = 0, n = 0, alen = 0;
    //pos指向的内存用于储存解析得到的结果
    char *pos = out + (*len);//传入的 *len = 0

    //开始解析name的报文
    while(1){
        flag = (int)sendBufferPointer[0];
        if(flag == 0){
            break;
        }
        else{
            sendBufferPointer++;
            memcpy(pos, sendBufferPointer, flag);
            pos += flag;
            sendBufferPointer += flag;

            *len += flag;
            if((int)sendBufferPointer[0] != 0){
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
}


int main(){
    //server端套接字文件描述符
    int sockfd;
    struct sockaddr_in server_addr;//本机地址
    struct sockaddr_in client_addr;//客户端地址
    size_t server_addr_len = sizeof(struct sockaddr_in);
    size_t client_addr_len = sizeof(struct client_addr);

    
    if(sockfd = socket(AF_INET, SOCK_DGRAM, 0) == -1){
        printf("socket创建出错\n");
        exit(1);
    }
    
    //发送缓冲区和接收缓冲区
    char sendbuf[512];
    char recvbuf[512];
    char *sendBufferPointer = sendbuf;
    char *recvBufferPointer = recvbuf;
    //初始化buffer
    memset(sendbuf, 0, 512);
    memset(recvbuf, 0, 512);

    //  <和client的UDP连接>
    //初始化server端套接字
    bzero(&server_addr,sizeof(server_addr));
    //用htons和htonl将端口和地址转成网络字节序
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(LOCAL_SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);//点分十进制地址转化为网络所用的二进制数，替换inter_pton

    //对于bind， accept之类的函数， 里面的套接字参数都是需要强制转化成（struct sockaddr *)
    //绑定服务器IP端口
    if(bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1){
        printf("bind出错\n");
        exit(-1);
    }
    printf("Server started. Waiting for data...\n");

    //接收request
    if(recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_len) == -1){
        printf("recvfrom出错\n");
        exit(-1);
    }

    struct Translate request;
    bzero(request, sizeof(struct Translate));
    int r_len = 0;
    //Header部分定长为24字节,跳过即可
    //request[12]开始是query name 的第一个数字
    sendBufferPointer += 12;
    DNS_Parse_Name(sendBufferPointer, request.domain, &r_len);
    sendBufferPointer += (r_len + 2);
    request.qtype = ntohs(*(unsigned short *)sendBufferPointer);
    sendBufferPointer += 2;
    r_len += 2;
    if(cacheSearch("E:\\Desktop\\demo.txt\n", request) == 0){
        memcpy(sendBufferPointer, &request, r_len);
        sendto(sockfd, sendbuf, strlen(sendbuf), 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        close(sockfd);
    }

    //  <和server的TCP连接>
    //建立与其他server的TCP连接
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    char *sendBufferPointer = sendbuf;
    char *recvBufferPointer = recvbuf;
    memset(sendbuf, 0, 512);
    memset(recvbuf, 0, 512);

    int 
}