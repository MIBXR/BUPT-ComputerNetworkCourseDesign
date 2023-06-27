#include "Header.h"
#pragma comment(lib,"wsock32.lib")
/* Set expire time of the specified record */
void Set_ID_Expire(ID_Trans_Unit* record, int ttl)
{
    record->expire_time = time(NULL) + ttl;   /* expire_time = time now + time to live */
}

/* Check whether the record is expired */
int Check_ID_Expired(ID_Trans_Unit* record)
{
    return record->expire_time > 0 && time(NULL) > record->expire_time;
}

/* Register new ID into ID_Trans_Table */
unsigned short Register_New_ID(unsigned short ID, SOCKADDR_IN temp, BOOL if_done)
{
    int i = 0;
    for (i = 0; i != MAX_ID_TRANS_TABLE_SIZE; ++i)
    {
        /* Find out overdue record or a record which was analysed completely */
        if (Check_ID_Expired(&ID_Trans_Table[i]) == 1 || ID_Trans_Table[i].done == TRUE)
        {
            ID_Trans_Table[i].old_ID = ID;     /* Set ID */
            ID_Trans_Table[i].client = temp;   /* socket_addr */
            ID_Trans_Table[i].done = if_done;  /* Mark whether analysis completed */
            Set_ID_Expire(&ID_Trans_Table[i], ID_EXPIRE_TIME);
            ID_Count++;
            if (debug_level)
            {
                printf("New ID : %d registered successfully\n", i + 1);
                printf("#ID Count : %d\n", ID_Count);
            }
            break;
        }
    }
    if (i == MAX_ID_TRANS_TABLE_SIZE) /* Register failed */
        return 0;
    return (unsigned short)i + 15; /* Return new ID */
}

/* Convert buf content to url and save into dest */
void Convert_to_Url (char* buf, char* dest)
{
    int i = 0, j = 0, k = 0, len = strlen(buf);
    while (i < len)
    {
        if (buf[i] > 0 && buf[i] <= 63) /* Count */
        {
            for (j = buf[i], i++; j > 0; j--, i++, k++) /* Copy the url */
                dest[k] = buf[i];
        }
        if (buf[i] != 0) /* If this is not the end, put a dot into dest */
        {
            dest[k] = '.';
            k++;
        }
    }
    dest[k] = '\0'; /* Set the end */
}

/* Output the whole packet */
void Output_Packet(char *buf,int length)
{
    unsigned char unit;
    printf("Packet length = %d\n", length);
    printf("Details of the package:\n");
    for(int i = 0; i < length; i++)
    {
        unit =(unsigned char)buf[i];
        printf("%02x ", unit);
    }
    printf("\n");
}

/* Receive packet from exterior */
void Receive_from_Extern()
{
    char buf[MAX_BUF_SIZE], url[URL_LENGTH];
    memset(buf, 0, MAX_BUF_SIZE);
    int length = -1;

    length = recvfrom(extern_sock, buf, sizeof(buf), 0, (struct sockaddr*)&external, &length_client); /* Receive DNS packet from exterior */
    //printf("the length is %d\n",length);
    if (length > -1)
    {
        printf("this is  extern \n");
        if (debug_level)
        {
            printf("\n\n---- Recv : Extern [IP:%s]----\n", inet_ntoa(external.sin_addr));

            /* Output time now */
            time_t t = time(NULL);
            char temp[64];
            strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
            printf("%s\n", temp);

            if (debug_level == 2)
                Output_Packet(buf, length);
        }

        /* Get ID index */
        unsigned short *pID = (unsigned short *)malloc(sizeof(unsigned short));
        memcpy(pID, buf, sizeof(unsigned short));
        int id_index = (*pID) - 15;
        free(pID);
        id_index = 0;


        /* Modify the packet ID to client ID */
        memcpy(buf, &id_index, sizeof(unsigned short));

        ID_Count--;
        if (debug_level >= 1)
            printf("#ID Count : %d\n", ID_Count);
        ID_Trans_Table[id_index].done = TRUE;

        /* Get info of client */
        client = ID_Trans_Table[id_index].client;

        /* Get number of queries and number of answers */
        int nquery = ntohs(*((unsigned short*)(buf + 4))), nresponse = ntohs(*((unsigned short*)(buf + 6)));
        char* p = buf + 12; /* p point to the Quetion field */
        char ip[16];
        int ip1, ip2, ip3, ip4;

        /* Read urls from queries, but only record last url */
        for (int i = 0; i < nquery; i++)
        {
            Convert_to_Url (p, url);
            while (*p > 0)
                p += (*p) + 1;
            p += 5; /* Point to the next query */
        }

        if (nresponse > 0 && debug_level >= 1)
            printf("Receive from extern [Url : %s]\n", url);

        /* Analyse the response */
        for (int i = 0; i < nresponse; ++i)
        {
            if ((unsigned char)*p == 0xc0) /* The name field is pointer */
                p += 2;
            else /* The name field is Url */
            {
                while (*p > 0)
                    p += (*p) + 1;
                ++p;
            }
            unsigned short resp_type = ntohs(*(unsigned short*)p);  /* Type */
            p += 2;
            unsigned short resp_class = ntohs(*(unsigned short*)p); /* Class */
            p += 2;
            unsigned long ttl = ntohl(*(unsigned long*)p); /* Time to live */
            p += 4;
            int datalen = ntohs(*(unsigned short*)p);  /* Data length */
            p += 2;
            if (debug_level >= 2)
                printf("Type -> %d,  Class -> %d,  TTL -> %d\n", resp_type, resp_class, ttl);

            if (resp_type == 1) /* Type A, the response is IPv4 address */
            {
                ip1 = (unsigned char)*p++;
                ip2 = (unsigned char)*p++;
                ip3 = (unsigned char)*p++;
                ip4 = (unsigned char)*p++;

                sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
                if (debug_level)
                    printf("IP address : %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);

                /* Add record to cache */
                printf("receive for exter url %s, ip %s\n", url,ip);
                Add_Record_to_Cache(url, ip);
                break;
            }
            else p += datalen;  /* If type is not A, then ignore it */
        }

        /* Send packet to client */
        length = sendto(local_sock, buf, length, 0, (SOCKADDR*)&client, sizeof(client));
    }
}

/* Receive packet from client */
void Receive_from_Local()
{
    char buf[MAX_BUF_SIZE], url[URL_LENGTH];
    memset(buf, 0, MAX_BUF_SIZE);
    int length = -1, output_cache_flag = 0;
    length = recvfrom(local_sock, buf, sizeof buf, 0, (struct sockaddr*)&client, &length_client);/* Receive packet from client */
    if (length > 0)
    {
        char ori_url[URL_LENGTH]; /* Original url */
        memcpy(ori_url, &(buf[DNS_HEAD_SIZE]), length); /* Get original url from packet */
        Convert_to_Url (ori_url, url); /* Convert original url to normal url */
        if (debug_level)
        {
            printf("\n\n---- Recv : Client [IP:%s]----\n", inet_ntoa(client.sin_addr));

            /* Output time now */
            time_t t = time(NULL);
            char temp[64];
            strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
            printf("%s\n", temp);

            printf("Receive from client [Query : %s]\n", url);
        }
        //  from now url is char *, but ip is string
        char ip[IP_LENGTH];

        int local_table_find_position = local_table_find(url);
        int cache_find_position = cache_find(url);

        if(local_table_find_position == -1 && cache_find_position == -1)
        {
            printf("[Url : %s] not in local data and cache\n", url);
            unsigned short *pID = (unsigned short *)malloc(sizeof(unsigned short));
            memcpy(pID, buf, sizeof(unsigned short)); /* Record ID */
            unsigned short nID = Register_New_ID(*pID, client, FALSE); /* Register in the ID transfer table */
            if (nID == 0)
            {
                if (debug_level >= 1)
                    printf("Register failed, the ID transfer table is full.\n");
            }
            else
            {
                memcpy(buf, &nID, sizeof(unsigned short));
                length = sendto(extern_sock, buf, length, 0, (struct sockaddr*)&extern_name, sizeof(extern_name));/* Send the request to external DNS server */
                if (debug_level >= 1)
                    printf("Send to external DNS server [Url : %s]\n", url);
            }
            free(pID);
        }
        else /* Url is in local data or cache */
        {
            if(local_table_find_position != -1)
            {
                strcpy(ip, table.local_table[local_table_find_position].ip);
                if (debug_level >= 1)
                    printf("Read from local data [Url:%s -> IP:%s]\n", url, ip);
            }
            else /* Cache */
            {
                strcpy(ip, table.cache[cache_find_position].ip);
                strcpy(tmp_data, url);
                change_element_to_first();
                if (debug_level >= 1)
                {
                    printf("cache ip : %s\n", table.cache[cache_find_position].ip);
                    printf("Read from cache [Url:%s -> IP:%s]\n", url, ip);
                    output_cache_flag = 1;
                }
            }
            char sendbuf[MAX_BUF_SIZE];
            memcpy(sendbuf, buf, length); /* Copy the request packet */
            unsigned short a = htons(0x8180);
            memcpy(&sendbuf[2], &a, sizeof(unsigned short)); /* Set the flags of Head */

            if (ip == "0.0.0.0")    /* Judge if the Url should be shielded */
                a = htons(0x0000);    /* Shielding function : set the number of answer to 0 */
            else a = htons(0x0001);    /* Server function : set the number of answer to 1 */
            memcpy(&sendbuf[6], &a, sizeof(unsigned short));

            int curLen = 0;
            char answer[16];
            unsigned short Name = htons(0xc00c);  /* Pointer of domain */
            memcpy(answer, &Name, sizeof(unsigned short));
            curLen += sizeof(unsigned short);

            unsigned short TypeA = htons(0x0001);  /* Type */
            memcpy(answer + curLen, &TypeA, sizeof(unsigned short));
            curLen += sizeof(unsigned short);

            unsigned short ClassA = htons(0x0001);  /* Class */
            memcpy(answer + curLen, &ClassA, sizeof(unsigned short));
            curLen += sizeof(unsigned short);

            unsigned long timeLive = htonl(0x7b); /* Time to live */
            memcpy(answer + curLen, &timeLive, sizeof(unsigned long));
            curLen += sizeof(unsigned long);

            unsigned short IPLen = htons(0x0004);  /* Data length */
            memcpy(answer + curLen, &IPLen, sizeof(unsigned short));
            curLen += sizeof(unsigned short);

            unsigned long IP = (unsigned long)inet_addr(ip); /* Actually data is IP */
            memcpy(answer + curLen, &IP, sizeof(unsigned long));
            curLen += sizeof(unsigned long);
            curLen += length;
            memcpy(sendbuf + length, answer, sizeof(answer));

            length = sendto(local_sock, sendbuf, curLen, 0, (SOCKADDR*)&client, sizeof(client)); /* Send the packet to client */

            if (length < 0)
                printf("Error : Send packet -> length < 0\n");

            char *p;
            p = sendbuf + length - 4;
            if (debug_level >= 1)
                printf("Send packet [Url:%s -> IP:%u.%u.%u.%u]\n", url, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
            if(output_cache_flag && debug_level)
                output_cache();
        }
    }
}

/* Set debug level and exterior DNS server address according to the parameters user provided */
void Process_Parameters(int argc, char* argv[])
{
    int user_set_dns_flag = 0;
    if (argc > 1 && argv[1][0] == '-')
    {
        if (argv[1][1] == 'd') debug_level++; /* Debug level add to 1 */
        if (argv[1][2] == 'd') debug_level++; /* Debug level add to 2 */
        if(argc > 2)
        {
            user_set_dns_flag = 1; /* If user set the dns server ip address */
            strcpy(DNS_Server_IP, argv[2]);
        }
    }
    if(user_set_dns_flag) /* If user set the dns server ip address */
        printf("Set DNS server : %s\n", argv[2]);
    else /* If user do not set the dns server ip address, set it by default */
        printf("Set DNS server : %s by default\n", DNS_Server_IP);
    if (argc > 3)
    {
        strcpy(file_path, argv[3]);
        printf("Read local data from file : \"%s\"\n", file_path);
    }
    printf("Read local data from file : \"%s\" by default\n", file_path);
    printf("Debug level : %d\n", debug_level);
}

/* Main Function */
int main(int argc, char* argv[])
{
    disp_head();/* Output at the beginning */

    /* Read and process the parameters user provided */
    Process_Parameters(argc, argv);
    header = NULL;
    /* Initialize the ID transfer table */
    for (int i = 0; i < MAX_ID_TRANS_TABLE_SIZE; i++)
    {
        ID_Trans_Table[i].old_ID = 0;
        ID_Trans_Table[i].done = TRUE;
        ID_Trans_Table[i].expire_time = 0;
        memset(&(ID_Trans_Table[i].client), 0, sizeof(SOCKADDR_IN));
    }

    WSAStartup(MAKEWORD(2, 2), &wsaData);  /* Initialize the WinSock service */

    /* Create local and exterior socket */
    local_sock = socket(AF_INET, SOCK_DGRAM, 0);
    extern_sock = socket(AF_INET, SOCK_DGRAM, 0);

    /* Set socket interface to non-blocking mode */
    int non_block = 1;
    ioctlsocket(extern_sock, FIONBIO, (u_long FAR*)&non_block);
    ioctlsocket(local_sock, FIONBIO, (u_long FAR*)&non_block);

    /* Check whether the creation of local socket is successful or failed */
    if (local_sock < 0)
    {
        if (debug_level >= 1)
            printf("Create local socket failed.\n");
        exit(1);
    }

    printf("Create local socket successfully.\n");

    local_name.sin_family = AF_INET;            /* Set the family as AF_INET (TCP/IP) */
    local_name.sin_addr.s_addr = INADDR_ANY;    /* Set to any */
    local_name.sin_port = htons(DNS_PORT);      /* Set the port as DNS port (53) */

    extern_name.sin_family = AF_INET;                         /* Set the family as AF_INET (TCP/IP) */
    extern_name.sin_addr.s_addr = inet_addr(DNS_Server_IP);   /* Set to the IP of extern DNS server */
    extern_name.sin_port = htons(DNS_PORT);                   /* Set the port as DNS port (53) */

    /* Set the socket option to avoid the port has been occupied */
    int reuse = 1;
    setsockopt(local_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    /* Bind local socket to the port */
    if (bind(local_sock, (struct sockaddr*)&local_name, sizeof(local_name)) < 0)
    {
        if (debug_level >= 1)
            printf("Bind socket port failed.\n");
        exit(1);
    }

    printf("Bind socket port successfully.\n");

    Read_Local_Data(); /* Read data from 'dnsrelay.txt' */

    while(TRUE)
    {
        Receive_from_Local();
        Receive_from_Extern();
    }
}
