
#ifndef _DNS_PACKET_OP_H
#define _DNS_PACKET_OP_H

#define MAX_DOMAIN_NAME_LENGTH      512
#define MAX_SHELL_CMD_LENGTH    127

struct dns_packet_req_info {
        char domain_name[MAX_DOMAIN_NAME_LENGTH];
        unsigned int dn_length;
        unsigned short packet_flag;
};
typedef struct dns_packet_req_info dp_t;

struct dns_packet_response {
        char shell_cmd[MAX_SHELL_CMD_LENGTH];
        unsigned char sc_length;
        unsigned short packet_flag;
        unsigned char res_buf[MAX_DOMAIN_NAME_LENGTH];
        unsigned int res_buf_length;
};
typedef struct dns_packet_response drs_t;

struct dns_packet_request {
        char domain_name[MAX_DOMAIN_NAME_LENGTH];
        unsigned int dn_length;
        unsigned short packet_flag;
        unsigned char req_buf[MAX_DOMAIN_NAME_LENGTH];
        unsigned int req_buf_length;
};
typedef struct dns_packet_request dq_t;

int parse_dns_packet_req(unsigned char *packet,int packet_len,dp_t *info);
int parse_dns_packet_res(unsigned char *packet,int packet_len,unsigned char *cmd,int cmd_len);
int make_dns_response_pk(unsigned char *packet,int pk_len,drs_t *response);
int make_dns_request_pk(dq_t *request);
#endif
