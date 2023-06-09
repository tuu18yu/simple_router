#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/*
    For every second the functions sends ARP request until it has been sent 5 times.
    Then, send ICMP host unreachable back to all packets waiting on this ARP request
*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
{
    /*  The implemented algorithm is from line 26-35 from sr_arpache.h:

        function handle_arpreq(req):
            if difftime(now, req->sent) > 1.0
                if req->times_sent >= 5:
                    send icmp host unreachable to source addr of all pkts waiting on this request
                    arpreq_destroy(req)
                else:
                    send arp request
                    req->sent = now
                    req->times_sent++ */
    printf("Handling ARP request \n");
    struct sr_arpcache *cache = &sr->cache;
    time_t now = time(0);
    if (difftime(now, req->sent) >= 1.0)
    {
        printf("1 second has passed \n");
        if ((req->times_sent) >= 5)
        {
            /* send icmp host unreachable to source addr of all pkts waiting on this request */
            printf("Request has sent more than 5 times \n");
            struct sr_packet *waiting_packet = req->packets;
            while (waiting_packet)
            {
                struct sr_if *waiting_iface = sr_get_interface(sr, waiting_packet->iface);
                send_icmp(sr, waiting_packet->buf, waiting_packet->len, waiting_iface, 3, 1);
                waiting_packet = waiting_packet->next;
            }
            sr_arpreq_destroy(cache, req);
        }
        else
        {
            /*  send arp request
                req->sent = now
                req->times_sent++ */
            printf("Request has sent less than 5 times \n");
            struct sr_packet *waiting_packet = req->packets;
            struct sr_if *waiting_iface = sr_get_interface(sr, waiting_packet->iface);

            /* send arp request packets back to the source of waiting packet */
            int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *arp_req_packet = (uint8_t *)malloc(len);
            
            printf("Initialize Ethernet Header \n");
            /* Set values for arp request packets ethernet header */
            sr_ethernet_hdr_t *arp_req_ether_hdr = (sr_ethernet_hdr_t *)(arp_req_packet);
            /* the source address is the address of router's current interface */
            memcpy(arp_req_ether_hdr->ether_shost, waiting_iface->addr, ETHER_ADDR_LEN);
            /* broadcast */
            memset(arp_req_ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
            arp_req_ether_hdr->ether_type = htons(ethertype_arp);

            printf("Initialize ARP Header \n");
            /* Set values for ARP header */
            sr_arp_hdr_t *arp_req_arp_hdr = (sr_arp_hdr_t *)(arp_req_packet + sizeof(sr_ethernet_hdr_t));
            arp_req_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
            arp_req_arp_hdr->ar_pro = htons(ethertype_ip);
            arp_req_arp_hdr->ar_hln = ETHER_ADDR_LEN;
            arp_req_arp_hdr->ar_pln = sizeof(uint32_t);
            arp_req_arp_hdr->ar_op = htons(arp_op_request);
            /* Sender is the router's current interface */
            memcpy(arp_req_arp_hdr->ar_sha, waiting_iface->addr, ETHER_ADDR_LEN);
            arp_req_arp_hdr->ar_sip = waiting_iface->ip;
            /* Target ip is the source of received request packet */
            memset(arp_req_arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
            arp_req_arp_hdr->ar_tip = req->ip;

            printf("Send ARP Request Packet \n");
            print_hdrs(arp_req_packet, len);
            printf("----------------\n");
            /* Send the arp request packet and free the malloc space */
            sr_send_packet(sr, arp_req_packet, len, waiting_iface->name);
            free(arp_req_packet);

            req->sent = now;
            req->times_sent++;
        }
    }
}

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr)
{
    /*  The implemented algorithm is from line 56-59 from sr_arpache.h:

        void sr_arpcache_sweepreqs(struct sr_instance *sr) {
            for each request on sr->cache.requests:
                handle_arpreq(request)
        }                                                               */

    struct sr_arpcache *cache = &sr->cache;
    struct sr_arpreq *request = cache->requests;
    struct sr_arpreq *next_request;

    /* Loop through all requests that is until request reaches null */
    while (request)
    {
        next_request = request->next;
        handle_arpreq(sr, request);
        request = next_request;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip))
        {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry)
    {
        copy = (struct sr_arpentry *)malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet, /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next)
    {
        if (req->ip == ip)
        {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req)
    {
        req = (struct sr_arpreq *)calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface)
    {
        struct sr_packet *waiting_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        waiting_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(waiting_pkt->buf, packet, packet_len);
        waiting_pkt->len = packet_len;
        waiting_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(waiting_pkt->iface, iface, sr_IFACE_NAMELEN);
        waiting_pkt->next = req->packets;
        req->packets = waiting_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next)
    {
        if (req->ip == ip)
        {
            if (prev)
            {
                next = req->next;
                prev->next = next;
            }
            else
            {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ)
    {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry)
{
    pthread_mutex_lock(&(cache->lock));

    if (entry)
    {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next)
        {
            if (req == entry)
            {
                if (prev)
                {
                    next = req->next;
                    prev->next = next;
                }
                else
                {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt)
        {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache)
{
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++)
    {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache)
{
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache)
{
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr)
{
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1)
    {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++)
        {
            if ((cache->entries[i].valid) && (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO))
            {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
