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
#define TLD_SERVER_IP "127.0.0.6"
#define TYPE_A        0X01
#define TYPE_CNMAE    0X05
#define TYPE_MX       0x0f

#define BufferSize 512
#define BACKLOG 10//最大同时请求连接数
#define AMOUNT 1500

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
    if(rr -> type == htons(0x000f)){
        memcpy(response + offset, &rr -> pre, sizeof(rr -> pre));
        offset += sizeof(rr -> pre);
    }
    memcpy(response + offset, rr -> rdata, strlen(rr -> rdata));
    offset += sizeof(rr -> rdata);
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

//检索本地txt文件
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
        // printf("%s\n", temp[i]);
        }
        i++;
    } 
    if(i == AMOUNT - 1) printf("The DNS record memory is full.\n");
    printf("first reader is ok\n");

    //把temp[i]切割成 IP 和 domain
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
        
        //到这没问题
        //如果Domain和Type匹对成功，创建response
        if(strcmp(cacheDomain, request -> domain) == 0 && tempType == request -> qtype){
            printf("same request exsit in cache\n");
            //生成response
            struct TCP_Header header = {0};
            TCP_Create_Header(&header);
            header.flags = htons(0x8000);
            header.authority = htons(0);
            header.answers = htons(0x0001);
            char *rtype;
            if(request -> qtype == 0x01){rtype = "A";}
            if(request -> qtype == 0x05){rtype = "CNAME";}
            if(request -> qtype == 0x0f){rtype = "MX";}//header.additional = htons(0x0001);
            struct DNS_Query query = {0};
            DNS_Create_Query(&query, cacheType, request -> domain);
            struct DNS_RR rr = {0};
            DNS_Create_RR(&rr, cacheDomain, atoi(cacheTTL), tempClass, tempType, cacheRdata);
            int tcplen = 18 + strlen(request -> domain) + 2 + strlen(cacheDomain) + 2 + strlen(cacheRdata) + 2 + 10; 
            header.length = htons(tcplen);
            if(request -> qtype == 0x0f){
                tcplen += 2;

            }
            int rlen = DNS_Create_Response(&header, &query, &rr, out, 512);
            return tcplen;
        }
        else{j++;}
    }
    printf("this is a new request\n");
    return -1;
}

int main(){
    int tcpsock;
    struct sockaddr_in tld_server_addr, local_server_addr;
    char recvBuffer[BufferSize];
    char sendBuffer[BufferSize];
    char *sendBufferPointer = sendBuffer;
    int lsa_len = sizeof(local_server_addr);

    bzero(&tld_server_addr, sizeof(tld_server_addr));
    tld_server_addr.sin_family = AF_INET;
    tld_server_addr.sin_port = htons(TLD_SERVER_PORT);
    tld_server_addr.sin_addr.s_addr = inet_addr("127.0.0.6");
    bzero(&local_server_addr, sizeof(local_server_addr));
    local_server_addr.sin_family = AF_INET;
    local_server_addr.sin_port = htons(LOCAL_SERVER_PORT_TEMP);
    local_server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);

    tcpsock = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpsock < 0){
        perror("com TCP socket创建出错\n");
        exit(-1);
    }

    int on = 1;
    if(setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
        perror("com TCP setsockopt出错\n ");
        exit(-1);
    }

    if(bind(tcpsock, (struct sockaddr *)&tld_server_addr, sizeof(tld_server_addr)) < 0){
        perror("com TCP bind出错\n");
        exit(-1);
    }

    if(listen(tcpsock, BACKLOG) < 0){
        perror("com TCP listen出错\n");
        exit(-1);
    }
    printf("com server is listening...\n");

    int consock;
    if((consock = accept(tcpsock, (struct sockaddr *)&local_server_addr, &lsa_len)) < 0){
        perror("com TCP accept出错\n");
        exit(-1);
    }

    if(recv(consock, recvBuffer, sizeof(recvBuffer), 0) < 0){
        perror("com TCP recv 出错\n");
        exit(-1);
    }

    //解析request
    printf("com server start to parse request\n");
    unsigned char *recvBufferPointer = recvBuffer;
    unsigned short qtype;
    int d_len = 0;
    int tempTTL = 86400;
    unsigned short tempType = 0x0001;
    unsigned short tempClass = 0x0001;
    char *apart[20];

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
    printf("domain : %s\n", request.domain);
    printf("qtype : %hd\n",request.qtype);

    // char *domain_dup = strdup(request.domain);
    // char *nextName = strtok(domain_dup, ".");
    // char *tldName;
    // char *t = tldName;
    // while(strcmp(nextName, "com") != 0){
    //     tldName = nextName;
    //     nextName = strtok(NULL, ".");
    // }
    // strcat(tldName,".com");
    // printf("tldName : %s\n",tldName);
    // struct Translate tldrequest = {0};
    // strcat(tldrequest.domain, tldName);
    // tldrequest.qtype = request.qtype;
    // printf("tldrequest domain : %s\n", tldrequest.domain);
    // int domainlen = strlen(tldrequest.domain);
    // printf("tldrequest qtype : %hd\n", tldrequest.qtype);

    //com为一步到位
    //开始检索
    int tcplen = cacheSearch("//home//fisheep//servers//com.txt", sendBufferPointer, &request);
    if(tcplen > 0){
        printf("cacheSerch successful!\n");
        if(send(consock, sendBuffer, tcplen + 2, 0) < 0){
        perror("com TCP send 出错\n");
        exit(-1);
        }
    }

    return 0;
}