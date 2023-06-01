#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNS_SERVER_PORT     53
#define DNS_SERVER_IP       "114.114.114.114"

#define DNS_HOST            0x01
#define DNS_CNAME           0x05


//dns报文Header部分数据结构
struct dns_header{
    unsigned short id; //2字节（16位）
    unsigned short flags; 

    unsigned short questions; //问题数
    unsigned short answer; //回答数

    unsigned short authority;
    unsigned short additional;
};

//dns报文Queries部分的数据结构
struct dns_question{
    int length; //主机名的长度，自己添加的，便于操作
    unsigned short qtype;
    unsigned short qclass;
    //查询名是长度和域名组合
    //如www.0voice.com ==> 60voice3com0
    //之所以这么做是因为域名查询一般是树结构查询，com顶级域，0voice二级域
    unsigned char *name; // 主机名（长度不确定）
};

//dns响应报文中数据（域名和ip）的结构体
struct dns_item{
    char *domain; 
    char *ip;
};



//将header部分字段填充数据
int dns_create_header(struct dns_header *header)
{
    if(header == NULL)
        return -1;
    memset(header, 0x00, sizeof(struct dns_header));

    //id用随机数,种子用time(NULL),表明生成随机数的范围
    srandom(time(NULL)); // 线程不安全
    header->id = random();
    
    //网络字节序（大端）地址低位存数据高位
    //主机(host)字节序转网络(net)字节序
    header->flags = htons(0x0100);
    header->questions = htons(0x0001);
    return 0;
}


//将Queries部分的字段填充数据
int dns_create_question(struct dns_question *question, const char *hostname)
{
    if(question == NULL || hostname == NULL)
        return -1;
    memset(question, 0x00, sizeof(struct dns_question));

    //内存空间长度：hostname长度 + 结尾\0 再多给一个空间
    question->name = (char *)malloc(strlen(hostname) + 2);
    if(question->name == NULL)
    {
        return -2;
    }

    question->length = strlen(hostname) + 2;

    //查询类型1表示获得IPv4地址
    question->qtype = htons(0x0001);
    //查询类1表示Internet数据
    question->qclass = htons(0x0001);

    //【重要步骤】
    //名字存储：www.0voice.com -> 3www60voice3com 
    const char delim[2] = ".";
    char *qname = question->name; //用于填充内容用的指针

    //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
    char *hostname_dup = strdup(hostname); //复制字符串，调用malloc
    //将按照delim分割出字符串数组，返回第一个字符串
    char *token = strtok(hostname_dup, delim);

    while(token != NULL)
    {
        //strlen返回字符串长度不含'\0'
        size_t len = strlen(token);

        *qname = len;//长度的ASCII码
        qname++;

        //将token所指的字符串复制到qname所指的内存上，最多复制len + 1长度 
        //len+1使得最后一个字符串把\0复制进去
        strncpy(qname, token, len + 1);
        qname += len;

        //固定写法，此时内部会获得下一个分割出的字符串返回（strtok会依赖上一次运行的结果）
        token = strtok(NULL, delim); //依赖上一次的结果，线程不安全
    }

    free(hostname_dup);       
}


//将header和question合并到request中
//request是传入传出参数
int dns_build_requestion(struct dns_header *header, struct dns_question *question, char *request, int rlen)
{
    if (header == NULL || question == NULL || request == NULL)
        return -1;

    memset(request, 0, rlen);

    //header -> request
    memcpy(request, header, sizeof(struct dns_header));
    int offset = sizeof(struct dns_header);

    //Queries部分字段写入到request中，question->length是question->name的长度
    memcpy(request + offset, question->name, question->length);
    offset += question->length;

    memcpy(request + offset, &question->qclass, sizeof(question->qclass));
    offset += sizeof(question->qclass);

    memcpy(request + offset, &question->qtype, sizeof(question->qtype));
    offset += sizeof(question->qtype);

    return offset; //返回request数据的实际长度
}

static int is_pointer(int in)
{
    //0xC0 : 1100 0000
    return ((in & 0xC0) == 0xC0);    
}

//从chunk的ptr指向的位置开始解析名字，长度写入len
static void dns_parse_name(unsigned char* chunk, unsigned char *ptr, char *out, int *len)
{
    int flag = 0, n = 0, alen = 0;
    //pos指向的内存用于存储解析得到的结果
    char *pos = out + (*len); // 传入的 *len = 0

    //???
    while(1)
    {
        flag = (int)ptr[0]; // ???
        if(flag == 0) break;

        if(is_pointer(flag))
        {
            n = (int)ptr[1];
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);
            break;
        }
        else //不是指针，表明是第一次出现Name的地方
        {
            ptr++;
            memcpy(pos, ptr, flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if((int)ptr[0] != 0)
            {
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
    
}

//解析响应
//struct dns_item** 是因为当struct dns_item *为NULL时需要改变其值
static int dns_parse_response(char *buffer, struct dns_item **domains)
{
    int i = 0;
    unsigned char *ptr = buffer;

    ptr += 4; // ptr向前4字节，指向Questions(问题数)字段开头
    int querys = ntohs(*(unsigned short *)ptr);

    ptr += 2; //ptr向前2字节，指向Answer RR回答数开头
    int answers = ntohs(*(unsigned short *)ptr); //一个域名可能对应多个ip

    ptr += 6; //ptr向前6字节，指向Queries(查询问题区域)Name字段的开头

    for(i = 0;i < querys; i++)
    {
        //如查询的网址为www.0voice,则Name = 3www60voice3com0 
        while(1)
        {
            int flag = (int)ptr[0];
            ptr += (flag + 1); //???

            if(flag == 0)   break;
        }
        ptr += 4; //指向下一个查询名Name字段的开头或跳过Type和Class字段
    }

    char cname[128], aname[128], ip[20], netip[4];
    int len, type, ttl, datalen;

    int cnt = 0;
    //动态分配内存的数组
    //分配answers个dns_item的内存，并全部置为0，返回指向一个位置的指针
    struct dns_item *list = calloc(answers, sizeof(struct dns_item));
    if(list == NULL)
    {
        return -1;
    }

    for(int i = 0;i < answers;++i)
    {
        bzero(aname, sizeof(aname));
        len = 0;

        //解析出域名
        dns_parse_name(buffer, ptr, aname, &len);
        ptr += 2;

        type = htons(*(unsigned short *)ptr);
        ptr += 4;

        ttl = htons(*(unsigned short *)ptr);
        ptr += 4;

        datalen = ntohs(*(unsigned short *)ptr);
        ptr += 2;

        if(type == DNS_CNAME)
        {
            bzero(cname, sizeof(cname));
            len = 0;
            //猜：从buffer的ptr位置开始解析出内容到cname中,len用来接受解析出的内容长度
            dns_parse_name(buffer, ptr, cname, &len);
            ptr += datalen;
        }
        else if(type == DNS_HOST)
        {
            bzero(ip, sizeof(ip));
            
            //ipv4为4字节
            if(datalen == 4)
            {
                memcpy(netip, ptr, datalen);
                //二进制网络字节序netip转为点分十进制地址存到ip
                inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
                
                printf("%s has address %s\n", aname, ip);
                printf("\t Time to live : %d minutes, %d seconds\n",ttl / 60, ttl % 60);

                list[cnt].domain = (char *)calloc(strlen(aname) + 1, 1);
                memcpy(list[cnt].domain, aname, strlen(aname));

                list[cnt].ip = (char *)calloc(strlen(ip) + 1, 1);
                memcpy(list[cnt].ip, ip, strlen(ip));

                cnt++;
            }

            ptr += datalen;
        }
    }
    *domains = list;
    ptr += 2; // 经测试这行不加也行

    return cnt;
}

//客户端向dns服务器发送请求
int dns_client_commit(const char *domain)
{
    //下方流程是基本定死的套路
    //1.创建UDP socket
    //网络层ipv4, 传输层用udp
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        return -1;
    }

    //2.结构体填充数据
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); //将结构体数组清空
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(DNS_SERVER_PORT);
    //点分十进制地址转为网络所用的二进制数 替换inet_pton
    //servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);
    inet_pton(AF_INET, DNS_SERVER_IP, &servaddr.sin_addr.s_addr);

    //UDP不一定要connect，只是这样提高成功发送请求的可能性
    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));


    //3.dns报文的数据填充
    struct dns_header header = {0};
    dns_create_header(&header);

    struct dns_question question = {0};

    dns_create_question(&question, domain);

    char request[1024] = {0};
    int len = dns_build_requestion(&header, &question, request, 1024);

    //4.通过sockfd发送DNS请求报文
    int slen = sendto(sockfd, request, len, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));

    char response[1024] = {0};
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);

    //5.接受DNS服务器的响应报文
    //addr和addr_len是输出参数
    int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr, (socklen_t *)&addr_len);

    struct dns_item *dns_domain = NULL;
    //6.解析响应
    dns_parse_response(response, &dns_domain);

    free(dns_domain);
    
    return n; //返回接受到的响应报文的长度
}

int main(int argc, char *argv[])
{
    if(argc < 2) return -1;
    dns_client_commit(argv[1]);
    return 0;
}
