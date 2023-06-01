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

#define LOCAL_SERVER_PORT 53
#define LOCAL_SERVER_IP   "127.0.0.2"

#define TYPE_A        0X01
#define TYPE_CNMAE    0X05
#define TYPE_MX       0x0f


//DNS header 和 question 部分结构体实现

//dns报文Header部分数据结构
struct DNS_Header{
    unsigned short id;  //2字节（16位）
    unsigned short flags;//省略定义，自己生成一个16位flag发送

    unsigned short questions;   //问题数
    unsigned short answers;  //回答数

    unsigned short authority;
    unsigned short additional;
};

//dns报文Queries部分的数据结构
struct DNS_Query{
    int length;//主机名的长度，自己添加的，便于操作
    unsigned short qtype;//查询类型
    unsigned short qclass;//查询类
    //查询名是长度和域名的组合
    unsigned char name[512];//主机名（长度不定！！）
};

//dns响应报文中数据（域名和ip）的结构体
struct DNS_RR{
    int length;
    unsigned char name[512];
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned char rdata[512];
};

//DNS Header部分数据填充
//完成主机字节序到网络字节序的转换
int DNS_Create_Header(struct DNS_Header *header){
    if(header == NULL)
        return -1;
    memset(header, 0x00, sizeof(struct DNS_Header));

    //id用随机数，种子用time（NULL），表明生成随机数的范围
    srandom(time(NULL));
    header -> id = random();

    //网络字节序（大端）地址低位存数据高位
    //主机(host)字节序转网络(net)字节序 host to net
    header -> flags = htons(0x0100);//query_flag = 0x0100
    header -> questions = htons(0x0001);
    header -> answers = htons(0);
    header -> authority = htons(0);
    header -> additional = htons(0);
    return 0;
}

//DNS Query部分数据填充
//用const定义的变量不可被修改，以防strlen计算长度时修改原字符串
int DNS_Create_Query(struct DNS_Query *query, const char *type, const char *hostname){
    if(query == NULL || hostname == NULL)
        return -1;
    //memset为初始化函数，Query为要填充的内存块，0x00为要被设置的值，sizeof...为被设置该值的字符数，返回指向Query的指针
    memset(query, 0x00, sizeof(struct DNS_Query));

    //内存空间长度：hostname长度 + 结尾\0 再多给一个空间
    //strlen()函数只读到‘\0’但不包含‘\0’，所以为了把结束符也复制进去，长度要+1。
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
    //www.baidu.com.3www5baidu3com 
    const char apart[2] = ".";
    char *qname = query -> name;//用于填充内容的指针

    //strdup先开辟大小与hostname同的内存，然后将hostname的字符拷贝到开辟的内存上
    char *hostname_dup = strdup(hostname);//复制字符串，调用malloc
    //将按照apart分割出字符串数组返回第一个字符串
    char *token = strtok(hostname_dup, apart);//strtok为分割函数，分割标识符apart

    while(token != NULL){
        //strlen返回的字符串长度不含‘\0’
        size_t len = strlen(token);

        *qname = len;//长度的ASCII码
        qname++;

        //将token所指的字符串复制到qname所指的内存上，最多复制len + 1 长度
        //len + 1 使得最后一个字符串把‘\0’复制进去
        strncpy(qname, token, len +1);//strcpy用于给字符数组赋值
        qname += len;

        //固定写法，此时内部会获得下一个分割出的字符串返回（strtok会依赖上一次运行的结果）
        token = strtok(NULL, apart);//依赖上一次的结果，线程不安全
    } 

    free(hostname_dup);
    return 0;
}

//合并header 和 queries.request
//input: header, query
//output: request
//rlen:代表request的长度
int DNS_Create_Requestion(struct DNS_Header *header, struct DNS_Query *query, char *request, int rlen){
    if(header == NULL || query == NULL || request == NULL)
        return -1;

    memset(request, 0, rlen);//初始化request

    //header.request
    memcpy(request, header, sizeof(struct DNS_Header));
    int offset = sizeof(struct DNS_Header);

    //query.request
    memcpy(request + offset, query -> name, query -> length + 1);
    offset += query -> length + 1;

    memcpy(request + offset, &query -> qtype, sizeof(query -> qtype));
    offset += sizeof(query -> qtype);

    memcpy(request + offset, &query -> qclass, sizeof(query -> qclass));
    offset += sizeof(query -> qclass);

    return offset;//返回request数据的实际长度
}

//
static int is_pointer(int in){
    //0xc0 : 1100 0000
    return((in & 0xc0) == 0xc0);
}
//从spoint的ptr指向位置开始解析名字，长度写入len
//返回的指针位置，在00后
static void DNS_Parse_Name(unsigned char* spoint, unsigned char *ptr, char *out, int *len){
    int flag = 0, n = 0, alen = 0;
    //pos指向的内存用于储存解析得到的结果
    char *pos = out + (*len);//传入的 *len = 0

    //开始解析name的报文
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
        //不是指针，表明是第一次出现name的地方
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

//解析response报文
static int DNS_Parse_Response(char *response){
    if(response == NULL){
        printf("No response!\n");
        return -1;
    }
    unsigned char *ptr = response;
    struct DNS_Header header = {0};
    //Header部分解析
    header.id = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到flags开头
    header.flags = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到questions开头
    header.questions = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到answers开头
    header.answers = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到authority开头
    header.authority = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到additional开头
    header.additional = ntohs(*(unsigned short *)ptr);
    ptr += 2;//跳到Query开头

    //Query部分解析
    struct DNS_Query *query = calloc(header.questions, sizeof(struct DNS_Query));
    for(int i = 0; i < header.questions; i++){
        // int query[i].length = 0;
        DNS_Parse_Name(response, ptr, query[i].name, &query[i].length);
        printf("query name: %s\n", query[i].name);
        ptr += (query[i].length + 2);

        query[i].qtype = ntohs(*(unsigned short *)ptr);
        printf("query type: %d\n", query[i].qtype);
        ptr += 2;//跳到qclass开头
        query[i].qclass = ntohs(*(unsigned short *)ptr);
        ptr += 2;
    }

    //Answer部分解析
    char ip[20],netip[4];
    struct DNS_RR *rr = calloc(header.answers, sizeof(struct DNS_RR));
    for(int i = 0; i < header.answers; i++){
        rr[i].length = 0;
        DNS_Parse_Name(response, ptr, rr[i].name, &rr[i].length);
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
            DNS_Parse_Name(response, ptr, rr[i].rdata, &rr[i].length);//length 是 rdata的长度
            ptr += rr[i].data_len;
            printf("%s has a cname of %s \n", rr[i].name, rr[i].rdata);
        }
        else if(rr[i].type == TYPE_A){
            bzero(ip,sizeof(ip));
            memcpy(netip, ptr, 4);
            DNS_Parse_Name(response, ptr, rr[i].rdata, &rr[i].length);//length 是 ip的长度
            ptr += rr[i].data_len;
            inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
            printf("%s has an address of %s \n", rr[i].name, ip);
        }
        else if(rr[i].type == TYPE_MX){
            // ptr += 2;//跳过preference
            DNS_Parse_Name(response, ptr, rr[i].rdata, &rr[i].length);
            ptr += (rr[i].data_len - 2);
            printf("%s has a Mail eXchange name of %s\n", rr[i].name, rr[i].rdata);
        }
    }
    return 0;
}






//发送request基本为固定格式
int DNS_Client_Commit(const char *type, const char *domain){
    //1.创建UDP socket
    //网络层IPv4,传输层UDP
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        return -1;
    }

    //2.结构体填充数据 填充服务器地址结构体数据
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));//将结构体数组清空
    servaddr.sin_family = AF_INET;//将服务器地址的协议族设置为AF_INET,AF_INET表示使用IPv4协议，初始化服务器地址结构体
    servaddr.sin_port = htons(LOCAL_SERVER_PORT);
    //点分十进制地址转为网络所用的二进制数 替换inter_pton
    //servaddr.sin_add.s_addr = inet_addr(DNS_SEVER_IP);
    inet_pton(AF_INET, LOCAL_SERVER_IP, &servaddr.sin_addr.s_addr);

    //UDP不一定要connect，只是这样提高成功发送请求的可能性
    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    //3.DNS报文的数据填充
    struct DNS_Header header = {0};
    DNS_Create_Header(&header);

    struct DNS_Query query = {0};
    DNS_Create_Query(&query, type, domain);

    char request[512] = {0};
    int len = DNS_Create_Requestion(&header, &query, request, 512);

    //4.通过sockfd发送DNS请求报文
    int slen = sendto(sockfd, request, len, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));

    char response[512] = {0};
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);

    //5.接受DNS服务器的响应报文
    //addr和addr_len是输出参数
    int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr, (socklen_t *)&addr_len);

    //6.解析响应
    DNS_Parse_Response(response);

    return n;//返回接受到响应报文的长度
}

int main(int argc, char *argv[])
{
    if(argc < 3) return -1;
    DNS_Client_Commit(argv[1], argv[2]);
    return 0;
}