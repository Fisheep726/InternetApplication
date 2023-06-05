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
#define TYPE_A        0X01
#define TYPE_CNMAE    0X05
#define TYPE_MX       0x0f

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


int DNS_Create_Query(struct DNS_Query *query, const char *type, const char *hostname){
    if(query == NULL || hostname == NULL)
        return -1;
    memset(query, 0x00, sizeof(struct DNS_Query));
    memset(query->name,0x00,512);
    if(query -> name ==NULL){
        return -2;
    }

    query -> length = strlen(hostname) + 1;//主机名占用内存长度

    //查询类型1表示获得IPv4地址  即 A
    unsigned short qtype;
    if(strcmp(type,"A") == 0)query -> qtype = htons(TYPE_A);
    if(strcmp(type,"MX") == 0)query -> qtype = htons(TYPE_MX);
    if(strcmp(type,"CNAME") == 0)query -> qtype = htons(TYPE_CNMAE);
    //查询类1表示Internet数据
    query -> qclass = htons(0x0001);

    //名字储存！！
    //www.baidu.com -> 3www5baidu3com 
    const char apart[2] = ".";
    char *qname = query -> name;//用于填充内容的指针
    //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
    char *hostname_dup = strdup(hostname);//复制字符串，调用malloc
    char *token = strtok(hostname_dup, apart);//strtok为分割函数，分割标识符apart

    while(token != NULL){
        size_t len = strlen(token);
        *qname = len;//长度的ASCII码
        qname++;
        strncpy(qname, token, len +1);//strcpy用于给字符数组赋值
        qname += len;
        token = strtok(NULL, apart);//依赖上一次的结果，线程不安全
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
    printf("rr type is : %hd\n", ntohs(rr -> type));
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
    //上面是request构造
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
    char *data = (char *)malloc(sizeof(char) *9);
    memcpy(data, rr -> rdata, strlen(rr -> rdata));
    printf("data : %s\n", data);
    memcpy(response + offset, rr -> rdata, strlen(rr -> rdata));
    offset += ntohs(rr -> data_len);
    
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
    char tempBuffer[BufferSize];
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

    int on = 1;
    if(setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
        perror("root TCP setsockopt出错\n ");
        exit(-1);
    }

    if(bind(tcpsock, (struct sockaddr *)&root_server_addr, sizeof(root_server_addr)) < 0){
        perror("root TCP bind出错\n");
        exit(-1);
    }

    if(listen(tcpsock, BACKLOG) < 0){
        perror("root TCP listen出错\n");
        exit(-1);
    }
    printf("root server is listening...\n");

    int consock;
    if((consock = accept(tcpsock, (struct sockaddr *)&local_server_addr, &lsa_len)) < 0){
        perror("root TCP accept出错\n");
        exit(-1);
    }

    if(recv(consock, recvBuffer, sizeof(recvBuffer), 0) < 0){
        perror("root TCP recv 出错\n");
        exit(-1);
    }

    int recvlen = strlen(recvBuffer);
    printf("recvlen : %d\n", recvlen);
    //解析request,获得顶级域名
    printf("root start parse request\n");
    unsigned char *recvBufferPointer = recvBuffer;
    char name[512];
    unsigned short qtype;
    int d_len = 0;
    int tempTTL = 86400;
    unsigned short tempType = 0x01;
    unsigned short tempClass = 0x01;
    char *apart[20];
    char *rootName;
    char *comip = "127.0.0.5";
    char *cacheType = "MX";

    //截取domain，跳过Header
    struct Translate request;
    bzero(&request, sizeof(struct Translate));
    int r_len = 0;
    //Header部分定长为12字节,跳过即可 tcp多了个length
    //request[14]开始是query name 的第一个数字
    recvBufferPointer += 14;
    DNS_Parse_Name(recvBufferPointer, request.domain, &r_len);
    recvBufferPointer += (r_len + 2);
    request.qtype = ntohs(*(unsigned short *)recvBufferPointer);
    recvBufferPointer += 2;
    r_len += 2;
    printf("parse request is ok\n");
    printf("recvbuffer[0] : %hd\n", ntohs(recvBuffer[0]));
    printf("rootname: %s\n",request.domain);
    printf("qtype: %hd\n",request.qtype);



    printf("start to response\n");
    //生成response
    struct DNS_Header header = {0};
    DNS_Create_Header(&header);
    header.flags = htons(0x8000);
    header.answers = htons(0x0001);
    struct DNS_Query query = {0};
    DNS_Create_Query(&query, cacheType, request.domain);
    struct DNS_RR rr = {0};
    // DNS_Create_RR(&rr, cacheDomain, atoi(cacheTTL), tempClass, tempType, cacheRdata);
    // int rlen = DNS_Create_Response(&header, &query, &rr, out, 512);



    //加入判断，决定返回的IP地址
    if(strcmp(rootName, "com") == 0){
        //返回com的TLD服务器IP
        DNS_Create_RR(&rr, rootName, tempTTL, tempClass, tempType, comip);
        int rrlen = DNS_Create_Response(&header, &query, &rr, &tempBuffer, 512);

    }

    if(strcmp(rootName, "org") == 0){
        //返回org的TLD服务器IP
        
    }

    if(strcmp(rootName, "cn") == 0){
        //返回cn的TLD服务器IP
    }

    if(strcmp(rootName, "us") == 0){
        //返回us的TLD服务器IP
    }

    if(send(consock, sendBuffer, strlen(sendBuffer), 0) < 0){
        perror("local TCP send 出错\n");
        exit(-1);
    }
}