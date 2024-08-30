#pragma once
#include <stdint.h>
#include <netinet/in.h>

typedef struct DNS_Client DNS_Client;

typedef struct DNS_MX_Answer
{
    uint16_t Pref;
    char     Data[64];
} DNS_MX_Answer;

DNS_Client*    dns_get_client(void);
in_addr_t      dns_get_iphost(DNS_Client* dns, const char* domain);
DNS_MX_Answer* dns_get_mxhost(DNS_Client* dns, const char* domain, int* len);

