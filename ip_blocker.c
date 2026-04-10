#include "postgres.h"
#include "libpq/auth.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/hsearch.h"
#include "nodes/pg_list.h"
#include "fmgr.h"
#include "storage/ipc.h"
#include <arpa/inet.h>

PG_MODULE_MAGIC;

typedef struct
{
    char ip_addr[NI_MAXHOST];
    bool is_malicious;
} IPBlockEntry;

static HTAB *blocklist_hash = NULL;

static ClientAuthentication_hook_type prev_client_auth_hook = NULL;

static bool is_ip_malicious(const char *remote_ip)
{
    // Implementing file parsing and/or hash lookup
    bool found = false;

    ereport(LOG,
            (errmsg("IP Blocker Extension: Checking if IP: %s is in the blocklist...", remote_ip)));

    hash_search(blocklist_hash, remote_ip, HASH_FIND, &found);

    ereport(LOG,
            (errmsg("IP Blocker Extension: Checking if IP: %s", HASH_FIND)));

    ereport(LOG,
            (errmsg("IP Blocker Extension: Result: %d", found)));

    return found;
}

static void ip_blocker_hook(Port *port, int status)
{
    char remote_ip[NI_MAXHOST];

    if (port->raddr.addr.ss_family == AF_INET || port->raddr.addr.ss_family == AF_INET6)
    {
        getnameinfo((struct sockaddr *)&port->raddr.addr, port->raddr.salen,
                    remote_ip, sizeof(remote_ip), NULL, 0, NI_NUMERICHOST);

        ereport(LOG,
                (errmsg("IP Blocker Extension: Attempted connection from IP: %s", remote_ip)));

        // DEBUG: Scan the whole hash table and print to logs
        /* HASH_SEQ_STATUS status_seq;
        IPBlockEntry *entry;

        hash_seq_init(&status_seq, blocklist_hash);
        ereport(LOG, (errmsg("IP Blocker: --- Dumping Hash Table ---")));

        while ((entry = hash_seq_search(&status_seq)) != NULL)
        {
            ereport(LOG, (errmsg("IP Blocker: Found in table: %s", entry->ip_addr)));
        }

        ereport(LOG, (errmsg("IP Blocker: --- End of Dump ---"))); */

        if (is_ip_malicious(remote_ip))
        {
            ereport(FATAL,
                    (errcode(ERRCODE_CONNECTION_EXCEPTION),
                     errmsg("Connection rejected: IP %s is on the blocklist.", remote_ip)));
        }
        else
        {
            ereport(LOG,
                    (errmsg("IP Blocker Extension: Connection allowed from IP: %s", remote_ip)));
        }
    }
    else
    {
        ereport(LOG,
                (errmsg("IP Blocker: Local/Unix socket connection detected (Skipping IP check)")));
    }

    if (prev_client_auth_hook)
        prev_client_auth_hook(port, status);
}

void _PG_init(void)
{
    ereport(LOG,
            (errmsg("IP Blocker Extension: Initialising...")));

    MemoryContext oldcontext;
    oldcontext = MemoryContextSwitchTo(TopMemoryContext);

    HASHCTL info;
    int flags;

    memset(&info, 0, sizeof(info));
    info.keysize = NI_MAXHOST;
    info.entrysize = sizeof(IPBlockEntry);
    flags = HASH_ELEM | HASH_STRINGS;

    blocklist_hash = hash_create("IP Blocklist", 1000, &info, flags);

    FILE *file = fopen(
        "/tmp/malicious_ip.txt",
        "r");

    if (file)
    {
        char line[NI_MAXHOST];
        while (fgets(line, sizeof(line), file))
        {
            line[strcspn(line, "\r\n")] = 0;

            if (line[0] == '\0')
                continue;

            bool found;
            IPBlockEntry *entry = (IPBlockEntry *)hash_search(
                blocklist_hash, line, HASH_ENTER, &found);

            if (found)
                ereport(LOG,
                        (errmsg("IP Blocker Extension: IP: %s is already in the blocklist...",
                                line)));
            else
                ereport(LOG,
                        (errmsg("IP Blocker Extension: IP: %s was added to the blocklist...",
                                entry->ip_addr)));
            entry->is_malicious = true;
        }
        fclose(file);
    }
    else
    {
        ereport(LOG,
                (errmsg("IP Blocker Extension: The blocklist file was not found.")));
    }

    MemoryContextSwitchTo(oldcontext);

    prev_client_auth_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = ip_blocker_hook;
}