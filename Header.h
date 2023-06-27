
#ifndef Header_h
#define Header_h

#include <winsock2.h>
#include <time.h>

#include <stdio.h>
#include <string.h>

#define MAX_BUF_SIZE 1024          /* Max buffer size */
#define DNS_PORT 53                /* DNS port */
#define MAX_ID_TRANS_TABLE_SIZE 16 /* MAX size of transfer table */
#define ID_EXPIRE_TIME 10          /* Expired time is 10s*/
#define MAX_CACHE_SIZE 5        /* Max size of cache */
#define DNS_HEAD_SIZE 12

#define MAX_LOCAL_TABLE 500
#define URL_LENGTH 650
#define IP_LENGTH 16

typedef struct url_ip
{
    char url[URL_LENGTH];
    char ip[IP_LENGTH];
}Url_Ip;

typedef struct table
{
    Url_Ip local_table[MAX_LOCAL_TABLE];
    int local_table_length;

    Url_Ip cache[MAX_CACHE_SIZE];
}Table;

Table table;
Table btable;
typedef struct list {
    char list_data[100];
    struct list* next;
}List;

List* header;
char tmp_data[100];
int cache_position = 0;

void add_local_table(char* url, char* ip, int cnt);
void add_cache(char* url, char* ip, int cnt);

int local_table_find(char *url);
int cache_find(char *url);
int cache_erase(char *url);
int cache_size(void);

void merge_sort(int l, int r);

/* Unit of ID transfer table */
typedef struct
{
    unsigned short old_ID; /* The old ID */
    BOOL done;             /* Mark whether the request was analysed completely */
    SOCKADDR_IN client;    /* Requestor socket address */
    int expire_time;       /* Expire time */
}ID_Trans_Unit;

int debug_level = 0; /* Debug level */
char DNS_Server_IP[16] = "10.3.9.4"; /* Extern DNS server IP default value */

char file_path[100] = "dnsrelay.txt"; /* Read data from this path */

ID_Trans_Unit ID_Trans_Table[MAX_ID_TRANS_TABLE_SIZE];    /* ID transfer table */
int ID_Count = 0; /* Size of ID transfer table */

WSADATA wsaData;  /* Store Windows Sockets initialization information */
SOCKET local_sock, extern_sock; /* Local socket and extern socket */

struct sockaddr_in local_name, extern_name;//AF_INET地址
struct sockaddr_in client, external;
int length_client = sizeof(client);

//list<string> cache_LRU_list;       /* Storage Url list for LRU algorithm */

List* create_list() /*Creat a list*/
{
    List* p;
    p = (List*)malloc(sizeof(List));
    int n = strlen(tmp_data);
    for (int i = 0; i <= n - 1; i++)
    {
        p->list_data[i] = tmp_data[i];
    }
    p->next = NULL;
    return p;
}

void traversal() /*Out LRU data*/
{
    List* p;
    int i = 0;
    for (p = header; p != NULL; p = p->next)
    {
        printf("%d. %s\n", i, p->list_data);
        i++;
    }
}

void get_the_last_element() /*Get the last element*/
{
    for (List* p = header; p != NULL;)
    {
        if (p->next != NULL)
        {
            p = p->next;
        }
        else
        {
            strcpy(tmp_data, p->list_data);
            p = NULL;
        }
    }
}

void delete_the_last_element() /*Delete the last element*/
{
    List* p1 = NULL;
    List* p = NULL;
    for (p = header; p != NULL;)
    {
        if (p->next != NULL)
        {
            p1 = p;
            p = p->next;
        }
        else
        {
            free(p);
            p = NULL;
            p1->next = NULL;
        }
    }
}

void add_the_first_element() /*Add_the_first_element*/
{
    List* p;
    p = (List*)malloc(sizeof(List));
    if (header != NULL)
    {
        strcpy(p->list_data, tmp_data);
        p->next = header;
        header = p;
    }
    else
    {
        strcpy(p->list_data, tmp_data);
        p->next = NULL;
        header = p;
    }
}

void change_element_to_first() /*Change_element_to_first*/
{
    List* p1 = NULL;
    for (List* p = header; p != NULL;)
    {
        if (p->next != NULL)
        {
            if (strcmp(p->list_data, tmp_data) == 0)
            {
                if (p == header)
                    break;
                else
                {
                    p1->next = p->next;
                    p->next = header;
                    header = p;
                    break;
                }
            }
            else
            {
                p1 = p;
                p = p->next;
            }
        }
        else
        {
            if (strcmp(p->list_data, tmp_data) == 0)
            {
                if (p == header)
                    break;
                else
                {
                    p1->next = NULL;
                    p->next = header;
                    header = p;
                    break;
                }
            }
            break;
        }
    }
}
/* Output cache table */
void output_cache()
{
    printf("\n\n--------------  Cache  --------------\n");
    int j = 0;

//    for (map<string,string>::iterator i = cache.begin(); i != cache.end(); i++)
//    {
//        printf("#%d Url:%s -> IP:%s\n",j++,i->first.c_str(), i->second.c_str());
//    }

    for (int i = 0; i < cache_size(); i++)
    {
        printf("%d. Url:%s -> IP:%s\n",j++,table.cache[i].url, table.cache[i].ip);
    }
    printf("-------------- LRU list--------------\n");
 //   for (list<string>::iterator i = cache_LRU_list.begin(); i != cache_LRU_list.end(); i++)
//    {
 //       if (i != cache_LRU_list.begin())printf("->");
 //       printf("%s\n", i->c_str());
 //   }
    traversal();
}

/* Output at the beginning */
void disp_head()
{
    printf("**********************************************************************\n");
    printf("* @Course Name: Course Design of Computer Network                    *\n");
    printf("* @Name of Team members: W J, C Y, X R					             *\n");
    printf("* ------------------------------------------------------------------ *\n");
    printf("*                       DNS Relay Server - Ver 1.1.4                 *\n");
    printf("**********************************************************************\n");
    printf("Command syntax : dnsrelay [-d | -dd] [dns-server-IP-addr] [file-path] \n");
    printf("Example : dnsrelay -dd 192.168.43.1 ./DATA/dnsrelay.txt               \n");
}

/* Read info from local data */
void Read_Local_Data()
{
    FILE* file;
    int cnt = 0;
    if ((file = fopen(file_path, "r")) == NULL) /* No such file then return */
        return;
    char url[URL_LENGTH], ip[IP_LENGTH];
    while (fscanf(file, "%s %s", ip, url) > 0)
    {
        if (debug_level >= 0)
            printf("Read from 'dnsrelay.txt' -> [Url : %s, IP : %s]\n", url, ip);
        //local_table[url] = ip;
        add_local_table(url, ip, cnt);
        cnt ++ ;
    }
    fclose(file);
    merge_sort(0, cnt - 1);
}

/* Add new record to cache */
void Add_Record_to_Cache(char* url, char* ip)
{
    int cache_find_position = 0;
    cache_find_position = cache_find(url);


    
    if(cache_find_position != -1)
    {
        strcpy(table.cache[cache_find_position].ip, ip);
    }



    else /* The record is not in cache */
    {
        if (cache_size() >= MAX_CACHE_SIZE) /* Cache is full (Use LRU algorithm) */
        {
//            string old_url = cache_LRU_list.back(); /* Get the last Url */
            get_the_last_element();
            char old_url[URL_LENGTH];
            strcpy(old_url,tmp_data);

            int cache_erase_position = cache_erase(old_url); /* Delete the old record in cache */
            strcpy(table.cache[cache_erase_position].ip, ip);
            strcpy(table.cache[cache_erase_position].url, url);
            
            /* Delete the old record in LRU list */
            delete_the_last_element();
        }

        else 
        {
            add_cache(url, ip, cache_position);
            cache_position++;
        }

        strcpy(tmp_data, url);
        add_the_first_element();
        output_cache();
    }
}


/**
 use to get the size of cache

 @return sizse of cahce
 */
int cache_size()
{
    int size=0;
    for(int i = 0; i < MAX_CACHE_SIZE; i++)
    {
        int j = 0;
        for(j = 0; j < IP_LENGTH && table.cache[i].ip[j] == '\0'; j++)
        {

        }
        if(j == IP_LENGTH)
        {
            size = i;
            break;
        }
        if(i == MAX_CACHE_SIZE - 1 && j != IP_LENGTH)
        {
            size = i + 1;
        }
    }
    return size;
}



/**
 to earse specific url and ip in cache

 @param url url need to 
 @return the earsed position
 */
int cache_erase(char *url)
{
    int ret = cache_find(url);
    for(int i = 0; i < URL_LENGTH; i++)
    {
        table.cache[ret].url[i] = '\0';
    }
    for(int i = 0; i < IP_LENGTH; i++)
    {
        table.cache[ret].ip[i] = '\0';
    }
    return ret;
}


void merge_sort(int l, int r)
{
    if (l == r)
        return;

    else
    {
        merge_sort((l + r) / 2 + 1, r);
        merge_sort(l, (l + r) / 2);
    }
    int t1 = l, t2 = (l + r) / 2 + 1, i;
    for (i = 1; i <= r - l + 1;)
    {
        if (t1 > (l + r) / 2)
        {
            for (; i <= r - l + 1; i++, t2++)
            {
                strcpy(btable.local_table[i].ip, table.local_table[t2].ip);
                strcpy(btable.local_table[i].url, table.local_table[t2].url);
            }
            break;
        }
        if (t2 > (r))
        {
            for (; i <= r - l + 1; i++, t1++)
            {
                strcpy(btable.local_table[i].ip, table.local_table[t1].ip);
                strcpy(btable.local_table[i].url, table.local_table[t1].url);
            }
            break;
        }

        if (strcmp(table.local_table[t1].url, table.local_table[t2].url) < 0)
        {
            strcpy(btable.local_table[i].ip, table.local_table[t1].ip);
            strcpy(btable.local_table[i].url, table.local_table[t1].url);
            t1++; i++;
            continue;
        }
        if (strcmp(table.local_table[t1].url, table.local_table[t2].url) > 0)
        {
            strcpy(btable.local_table[i].ip, table.local_table[t2].ip);
            strcpy(btable.local_table[i].url, table.local_table[t2].url);
            t2++; i++;
            continue;
        }
        if (strcmp(table.local_table[t1].url, table.local_table[t2].url) == 0)
        {
            strcpy(btable.local_table[i].ip, table.local_table[t1].ip);
            strcpy(btable.local_table[i].url, table.local_table[t1].url);
            strcpy(btable.local_table[i + 1].ip, table.local_table[t2].ip);
            strcpy(btable.local_table[i].url, table.local_table[t2].url);
            t1++; t2++;
            i = i + 2;
            continue;
        }
    }
    for (i = 1; i <= r - l + 1; i++)
    {
        strcpy(table.local_table[i + l - 1].ip, btable.local_table[i].ip);
        strcpy(table.local_table[i + l - 1].url, btable.local_table[i].url);
    }
}


/**
 find url and ip in local table

 @param url url need to find
 @return position of url in local table
 */
int local_table_find(char* url)
{
    if (table.local_table_length == 0) return -1;
    int begin = 0;    //起始位置
    int end = table.local_table_length - 1;    //末尾位置
    int mid = (begin + end) / 2;    //要查找的中间位置

    while (begin <= end)
    {
        if (strcmp(url, table.local_table[mid].url) == 0)
        {    //返回找到的位置
            return mid;
        }
        else if (strcmp(url, table.local_table[mid].url) < 0)
        {    //如果中间位置的值比所要找的值大，那么末尾位置指向中间位置的上一个位置
            end = mid - 1;
        }
        else
        {    //如果中间位置的值比所要找的值小，那么起始位置指向中间位置的下一个位置
            begin = mid + 1;
        }
        mid = (begin + end) / 2;
    }
    return -1;
}
/*
int local_table_find(char *url)
{
    int ret = 0;
    for(int i = 0;i < table.local_table_length; i++)
    {
        if(strcmp(url,table.local_table[i].url) == 0 )
        {
            ret = i;
            break;
        }
        else
        {
            ret = -1;
        }
    }
    return ret;
}
*/

/**
 find url and ip in cache

 @param url url need to find
 @return position of url in cache
 */
int cache_find(char *url)
{
    int ret = 0;
    for(int i = 0;i < MAX_CACHE_SIZE; i++)
    {
        if(strcmp(url,table.cache[i].url) == 0 )
        {
            ret = i;
            break;
        }
        else
        {
            ret = -1;
        }
    }
    return ret;
}


/**
 add url and ip in local table

 @param url url
 @param ip ip
 @param cnt the position of table to insert
 */
void add_local_table(char* url, char* ip, int cnt)
{
    if(strlen(url) > URL_LENGTH)
    {
        strncpy(table.local_table[cnt].url, url, 64);
        table.local_table[cnt].url[64] = '\0';
    }
    else
    {
        strcpy(table.local_table[cnt].url, url);
    }
    strcpy(table.local_table[cnt].ip, ip);
    table.local_table_length = cnt + 1;  // from 0 to count, and length is > 0
}


/**
 add url and ip in cache

 @param url url
 @param ip ip
 @param cnt the position of table to insert
 */
void add_cache(char* url, char* ip, int cnt)
{
    if(strlen(url) > URL_LENGTH)
    {
        table.local_table[cnt].url[64] = '\0';
    }
    else
    {
        strcpy(table.cache[cnt].url, url);
    }
    strcpy(table.cache[cnt].ip, ip);
}
#endif