#include <cstring>
#include <cassert>
#include <cstdint>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

struct DNS_A
{
    in_addr_t Data;
};

struct DNS_MX
{
    uint16_t Pref;
    char     Data;
};

struct DNS_Header
{
    uint16_t ID;
    uint16_t Flags;
    uint16_t Quest;
    uint16_t Ans;
    uint16_t AuthRR;
    uint16_t AdditionalRR;
};

struct DNS_Answer
{
    uint16_t Type;
    uint16_t Class;
    uint32_t TTL;
    uint16_t DataLen;

    union
    {
        DNS_A   A;
        DNS_MX MX;
    } Data;

} __attribute__((packed));

struct DNS_MX_Answer
{
    uint16_t Pref;
    char     Data[64];
};

struct DNS_Question
{
    uint16_t Type;
    uint16_t Class;
};

enum DNS_Type : uint16_t
{
    T_A   = 0x0100,
    T_NS  = 0x0200,
    T_SOA = 0x0600,
    T_MX  = 0x0F00,
};

struct DNS_Client
{
    DNS_Client();
    ~DNS_Client();

    void        SendRequest(const char* domain, enum DNS_Type type);
    DNS_Answer* SkipAnswerName(const char* data);

    void        Parse_MX_Record(const char* src, char* dst);
    void        Parse_MX_Request();
    in_addr_t   Parse_A_Request();
    in_addr_t   GetNameServer();

    int         Sock;
    char*       Packet;
    uint32_t    PacketLen;
    uint16_t    TransID;
    sockaddr_in Dest;

    std::vector<DNS_MX_Answer> Results;
};


DNS_Client::DNS_Client()
{
    srand(time(nullptr));
    Results.reserve(6);

    Packet = new char[1024];
    Sock   = socket(AF_INET, SOCK_DGRAM, 0);
    assert(Sock != -1);
    assert(Packet);

    Dest.sin_family      = AF_INET;
    Dest.sin_port        = htons(53);
    Dest.sin_addr.s_addr = GetNameServer();
}

DNS_Client::~DNS_Client()
{
    close(Sock);
    delete[] Packet;
}

in_addr_t DNS_Client::GetNameServer()
{
    std::string       line;
    std::ifstream     file;
    std::stringstream ss;

    file.open("/etc/resolv.conf");

    if (!file.is_open())
        return 0;

    while (std::getline(file, line))
    {
        if (line.find("nameserver") == 0)
        {
            ss << line;
            ss >> line >> line;
            break;
        }
    }

    file.close();
    return inet_addr(line.c_str());
}

DNS_Answer* DNS_Client::SkipAnswerName(const char* data)
{
    while (*data != '\0')
    {
        if (((uint8_t)*data & 0xC0) == 0xC0)
            return (DNS_Answer*)(data + 2);

        data += *data + 1;
    }

    return (DNS_Answer*)(data + 1);
}

in_addr_t DNS_Client::Parse_A_Request()
{
    DNS_Header* header;
    DNS_Answer* answer;

    header = (DNS_Header*) Packet;
    recvfrom(Sock, Packet, 1024, 0, nullptr, 0);

    if (header->ID != TransID)
        return 0;

    if (header->Ans == 0)
        return 0;

    answer = SkipAnswerName(Packet + PacketLen);
    return answer->Data.A.Data;
}

void DNS_Client::Parse_MX_Request()
{
    char*          answer_start;
    DNS_Header*    header;
    DNS_Answer*    answer;
    DNS_MX_Answer* newest;

    header = (DNS_Header*) Packet;
    recvfrom(Sock, Packet, 1024, 0, nullptr, 0);

    if (header->ID != TransID)
        return;

    Results.clear();
    answer_start = Packet + PacketLen;

    for (int i = 0; i < htons(header->Ans); ++i)
    {
        answer = SkipAnswerName(answer_start);

        if (answer->Type == T_MX)
        {
            Results.emplace_back();
            newest = &Results.back();

            Parse_MX_Record(&answer->Data.MX.Data, newest->Data);
            newest->Pref = htons(answer->Data.MX.Pref);
        }
        
        answer_start = (char*)&answer->Data + htons(answer->DataLen);
    }
}

void DNS_Client::Parse_MX_Record(const char* src, char* dst)
{
    uint32_t i;
    uint32_t j;
    uint32_t len;
    uint16_t label;

    label = htons(*(uint16_t*)src);

    if ((label & 0xC000) == 0xC000)
        src = Packet + (label & 0x3FFF);

    len = *src + 1;

    for (i = 1, j = 0; src[i] != '\0' && j < 64; ++i, ++j)
    {
        if (i == len)
        {
            if (((uint8_t)src[i] & 0xC0) == 0xC0)
            {
                src = Packet + (htons(*(uint16_t*)(src+i)) & 0x3FFF);
                len = i = 0;
            }

            len   += src[i] + 1;
            dst[j] = '.';

            continue;
        }

        dst[j] = src[i];
    }

    dst[j] = '\0';
}

void DNS_Client::SendRequest(const char* domain, enum DNS_Type type)
{
    DNS_Question* query;
    DNS_Header*   header = (DNS_Header*)Packet;
    char*         buffer = Packet + sizeof(DNS_Header);
    
    int i =  0;
    int j =  1;
    int d = -1;

    while (domain[i] != '\0')
    {
        if (domain[i] == '.')
        {
            buffer[d+1] = i-d-1;
            d = i;
        }

        buffer[j++] = domain[i++];
    }
    
    PacketLen   = sizeof(DNS_Header)+j+5;
    buffer[j]   = 0;
    buffer[d+1] = i-d-1;

    memset(header, 0, sizeof(DNS_Header));
    header->ID    = (TransID = rand() % 65536);
    header->Flags = 0x0001;
    header->Quest = 0x0100;

    query        = (DNS_Question*)(Packet + PacketLen - 4);
    query->Type  = type;
    query->Class = 0x0100;

    sendto(Sock, Packet, PacketLen, 0,
          (sockaddr*)&Dest, sizeof(Dest));
}

extern "C" DNS_Client* dns_get_client()
{
    static DNS_Client client;
    return &client;
}

extern "C" in_addr_t dns_get_iphost(DNS_Client* dns, const char* domain)
{
    dns->SendRequest(domain, T_A);
    return dns->Parse_A_Request();
}

extern "C" DNS_MX_Answer* dns_get_mxhost(DNS_Client* dns, const char* domain, int* len)
{
    dns->SendRequest(domain, T_MX);
    dns->Parse_MX_Request();

    *len = dns->Results.size();
    return dns->Results.data();
}
