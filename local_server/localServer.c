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

    if(type == 0x0005 || type == 0x000f){
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

int TCP_Create_Requestion(struct TCP_Header *header, struct DNS_Query *query, char *request, int rlen){
    if(header == NULL || query == NULL || request == NULL)
        return -1;

    memset(request, 0, rlen);//初始化request

    //header.request
    memcpy(request, header, sizeof(struct TCP_Header));
    int offset = sizeof(struct TCP_Header);

    //query.request
    memcpy(request + offset, query -> name, query -> length + 1);
    offset += query -> length + 1;

    memcpy(request + offset, &query -> qtype, sizeof(query -> qtype));
    offset += sizeof(query -> qtype);

    memcpy(request + offset, &query -> qclass, sizeof(query -> qclass));
    offset += sizeof(query -> qclass);

    return offset;//返回request数据的实际长度
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

static int TCP_Parse_Response(char *response){
    if(response == NULL){
        printf("No response!\n");
        return -1;
    }
    unsigned char *ptr = response;
    struct TCP_Header header = {0};
    //Header部分解析
    header.length = ntohs(*(unsigned short *)ptr);
    printf("header.length : %hd\n", header.length);
    ptr += 2;
    header.id = ntohs(*(unsigned short *)ptr);
    printf("header.id : %hd\n", header.id);
    ptr += 2;//跳到flags开头
    header.flags = ntohs(*(unsigned short *)ptr);
    printf("header.flag : %hd\n", header.flags);
    ptr += 2;//跳到questions开头
    header.questions = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到answers开头
    printf("header.questions : %hd\n", header.questions);
    header.answers = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到authority开头
    header.authority = ntohs(*(unsigned short *)ptr);
    printf("header.authority : %hd\n", header.authority);
    ptr += 2;//跳到additional开头
    header.additional = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到Query开头

    //Query部分解析
    struct DNS_Query *query = calloc(header.questions, sizeof(struct DNS_Query));
    for(int i = 0; i < header.questions; i++){
        // int query[i].length = 0;
        DNS_Parse_Name(ptr, query[i].name, &query[i].length);
        // if(query[i].name != 0){printf("query name: %s\n", query[i].name);}
        ptr += (query[i].length + 2);

        query[i].qtype = ntohs(*(unsigned short *)ptr);
        if(query[i].qtype != 0){printf("query type: %d\n", query[i].qtype);}
        if(query[i].qtype != 0){printf("query name: %s\n", query[i].name);}
        ptr += 2;//跳到qclass开头
        query[i].qclass = ntohs(*(unsigned short *)ptr);
        ptr += 2;
    }

    //Answer部分解析
    char ip[20],netip[4];
    struct DNS_RR *rr = calloc(header.answers, sizeof(struct DNS_RR));
    if(header.answers > 0){
        for(int i = 0; i < header.answers; i++){
            rr[i].length = 0;
            DNS_Parse_Name(ptr, rr[i].name, &rr[i].length);
            printf("answer%d name: %s\n", i, rr[i].name);
            printf("rrlength : %d\n", rr[i].length);
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

            //判断type
            if(rr[i].type == TYPE_CNMAE){
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);//length 是 rdata的长度
                ptr += rr[i].data_len;
                printf("%s has a cname of %s \n", rr[i].name, rr[i].rdata);
            }
            else if(rr[i].type == TYPE_A){
                bzero(ip,sizeof(ip));
                memcpy(netip, ptr, 4);
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);//length 是 ip的长度
                ptr += rr[i].data_len;
                inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
                printf("%s has an address of %s \n", rr[i].name, ip);
            }
            else if(rr[i].type == TYPE_MX){
                // ptr += 2;//跳过preference
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
            ptr += 2;

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

            //判断type
            if(rr[i].type == TYPE_CNMAE){
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);//length 是 rdata的长度
                ptr += rr[i].data_len;
                printf("%s has a cname of %s \n", rr[i].name, rr[i].rdata);
            }
            else if(rr[i].type == TYPE_A){
                bzero(ip,sizeof(ip));
                memcpy(netip, ptr, 4);
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);//length 是 ip的长度
                ptr += rr[i].data_len;
                inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
                printf("%s has an address of %s \n", rr[i].name, ip);
            }
            else if(rr[i].type == TYPE_MX){
                // ptr += 2;//跳过preference
                DNS_Parse_Name(ptr, rr[i].rdata, &rr[i].length);
                ptr += (rr[i].data_len - 2);
                printf("%s has a Mail eXchange name of %s\n", rr[i].name, rr[i].rdata);
            }
        }
    }

    return 0;
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
    unsigned char *recvfromBufferPointer = recvfromBuffer;
    //初始化buffer
    // memset(sendtoBuffer, 0, BufferSize);
    // memset(recvfromBuffer, 0, BufferSize);

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

    //解析request
    struct Translate request;
    bzero(&request, sizeof(struct Translate));
    int r_len = 0;
    //Header部分定长为24字节,跳过即可
    //request[12]开始是query name 的第一个数字
    recvfromBufferPointer += 12;
    DNS_Parse_Name(recvfromBufferPointer, request.domain, &r_len);
    recvfromBufferPointer += (r_len + 2);
    request.qtype = ntohs(*(unsigned short *)recvfromBufferPointer);
    recvfromBufferPointer += 2;
    r_len += 16;
    printf("parse request is ok\n");
   


    int rrlen = cacheSearch("//home//fisheep//demo.txt",sendtoBufferPointer, &request);
    if(rrlen > 0){
        //cache中存在,返回response
        printf("cacheSerch successful!\n");
        sendto(udpsock, sendtoBuffer, rrlen, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if(sendto < 0){
            perror("local UDP sendto 出错\n");
            exit(-1);
        }
        // close(udpsock);
        return 0;
    }
    printf("Start to build TCP\n");
    //TCP
    int tcpsock;
    struct sockaddr_in root_server_addr, local_server_addr;
    char recvBuffer[BufferSize];
    char sendBuffer[BufferSize];
    char *sendBufferPointer = sendBuffer;

    bzero(&local_server_addr, sizeof(local_server_addr));
    local_server_addr.sin_family = AF_INET;
    local_server_addr.sin_port = htons(LOCAL_SERVER_PORT);
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
    //创建tcp request
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
    int tcplen = 20 + strlen(request.domain) + 1;
    header.length = htons(tcplen);
    int totallen = 0;
    totallen = TCP_Create_Requestion(&header, &query, TCPrequestPointer, tcplen);

     //传输信息
    if(send(tcpsock, &TCPrequest, totallen + 2, 0) < 0){
        perror("local TCP send 出错\n");
        exit(-1);
    }

    if(recv(tcpsock, recvBuffer, sizeof(recvBuffer), 0) < 0){
        perror("local TCP recv 出错\n");
        exit(-1);
    }
    TCP_Parse_Response(recvBuffer);
    return 0;
}