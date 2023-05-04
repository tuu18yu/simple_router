#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void handle_arp(struct sr_instance *sr,
                uint8_t *packet /* lent */,
                unsigned int len,
                char *interface /* lent */);

void handle_ip(struct sr_instance *sr,
               uint8_t *packet /* lent */,
               unsigned int len,
               char *interface /* lent */);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  if (len < sizeof(sr_ethernet_hdr_t))
  {
    fprintf(stderr, "Error: Packet is too small\n");
    return;
  }

  if (ethertype(packet) == ethertype_ip)
  {
    printf("Received packet is IP\n");
    handle_ip(sr, packet, len, interface);
  }

  else if (ethertype(packet) == ethertype_arp)
  {
    printf("Received packet is ARP\n");
    handle_arp(sr, packet, len, interface);
  }

} /* end sr_ForwardPacket */

void handle_arp(struct sr_instance *sr,
                uint8_t *packet /* lent */,
                unsigned int len,
                char *interface /* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
  {
    fprintf(stderr, "Error: Packet is too small\n");
    return;
  }
  sr_ethernet_hdr_t *received_ether_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_arp_hdr_t *received_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *current_interface = sr_get_interface(sr, interface);

  /* ARP packet is a request for IP address*/
  if (arp_op_request == ntohs(received_arp_hdr->ar_op))
  {
    /* The current interface of the router does not have the requested IP address*/
    if (received_arp_hdr->ar_tip != current_interface->ip)
    {
      printf("ARP packet is not targeting this interface\n");
      return;
    }
    printf("ARP packet is requesting");
    /* Send reply packet containing information of the current interface to the sender of ARP packet*/
    uint8_t *reply_packet = (uint8_t *)malloc(len);

    /* Set values for reply ethernet header */
    sr_ethernet_hdr_t *reply_ether_hdr = (sr_ethernet_hdr_t *)(reply_packet);
    /* the source address is the address of router's current interface */
    memcpy(reply_ether_hdr->ether_shost, current_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    /* the destination address is the source address of received packet */
    memcpy(reply_ether_hdr->ether_dhost, received_ether_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    reply_ether_hdr->ether_type = htons(ethertype_arp);

    /* Set values for reply ARP header */
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_arp_hdr->ar_hrd = received_arp_hdr->ar_hrd;
    reply_arp_hdr->ar_pro = received_arp_hdr->ar_pro;
    reply_arp_hdr->ar_hln = received_arp_hdr->ar_hln;
    reply_arp_hdr->ar_pln = received_arp_hdr->ar_pln;
    reply_arp_hdr->ar_op = htons(arp_op_reply);
    /* Sender of the reply packet is the router's current interface */
    memcpy(reply_arp_hdr->ar_sha, current_interface->addr, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip = current_interface->ip;
    /* Target of the reply packet is the source of received packet */
    memcpy(reply_arp_hdr->ar_tha, received_ether_hdr->ether_shost, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_tip = received_arp_hdr->ar_sip;

    /* Send the reply packet to the sender and free the malloc space */
    sr_send_packet(sr, reply_packet, len, interface);
    free(reply_packet);
  }

  /* ARP packet is a reply with information of the sender to the current interface */
  else if (arp_op_reply == ntohs(received_arp_hdr->ar_op))
  {
    printf("ARP packet is replying");
    /* The implemented algorithm is from line 39-47 from sr_arpache.h:

    The ARP reply processing code should move entries from the ARP request
    queue to the ARP cache:

    # When servicing an arp reply that gives us an IP->MAC mapping
    req = arpcache_insert(ip, mac)

    if req:
      send all packets on the req->packets linked list
      arpreq_destroy(req) */

    struct sr_arpcache *cache = &(sr->cache);
    unsigned char *mac = received_arp_hdr->ar_sha;
    uint32_t ip = received_arp_hdr->ar_sip;
    struct sr_arpreq *req = sr_arpcache_insert(cache, mac, ip);

    /* If succesfully inserted to the router's cache*/
    if (req)
    {
      struct sr_packet *waiting_packet = req->packets;
      /*Send all packets waiting for the request to finish*/
      while (waiting_packet)
      {
        /*Initialize header for the raw ethernet frame of the waiting packet*/
        sr_ethernet_hdr_t *waiting_ether_hdr = (sr_ethernet_hdr_t *)waiting_packet->buf;
        /* the source address is the address of router's current interface */
        memcpy(waiting_ether_hdr->ether_shost, current_interface->addr, ETHER_ADDR_LEN);
        /* the destination address is the source address of received packet */
        memcpy(waiting_ether_hdr->ether_dhost, received_arp_hdr->ar_sha, ETHER_ADDR_LEN);

        /* Send the waiting packet to the sender and set to the next packet until NULL*/
        sr_send_packet(sr, waiting_packet->buf, waiting_packet->len, interface);
        waiting_packet = waiting_packet->next;
      }
      /* Free all memory associated with this arp request entry*/
      sr_arpreq_destroy(cache, req);
    }
  }
}

int is_for_me(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr)
{
  int result = 0;
  struct sr_if *iface = sr->if_list;

  if (iface->ip == ip_hdr->ip_dst)
  {
    result = 1;
  }
  else
  {
    while (iface == iface->next)
    {
      if (iface->ip == ip_hdr->ip_dst)
      {
        result = 1;
        break;
      }
    }
  }
  return result;
}

void handle_ip(struct sr_instance *sr,
               uint8_t *packet /* lent */,
               unsigned int len,
               char *interface /* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_if *iface = sr_get_interface(sr, interface);                     /* ethernet interface*/
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)); /* ip header*/
  sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)packet;

  /* Sanity-check the packet (meets minimum length and has correct checksum).*/
  int minLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  if (len < minLen)
  {
    fprintf(stderr, "Error: Packet is too small\n");
    return;
  }
  uint16_t received_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0; /*Change packet check sum for calculation.*/
  uint16_t checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  if (checksum != received_cksum)
  {
    fprintf(stderr, "Error: Packet checksum not matching with calculated result\n");
    return;
  }

  if (is_for_me(sr, ip_hdr))
  {
    if (ip_hdr->ip_p == ip_protocol_icmp)
    {
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + minLen);
      /* sanity check*/
      int icmpMinLen = minLen + sizeof(sr_icmp_hdr_t);
      if (len < icmpMinLen)
      {
        fprintf(stderr, "Error: Packet is too small\n");
        return;
      }
      int checksum = cksum(icmp_hdr, len - minLen);
      if (checksum != icmp_hdr->icmp_sum)
      {
        fprintf(stderr, "Error: Packet has incorrect checksum\n");
        return;
      }

      if (icmp_hdr->icmp_type == 8)
      { /* ICMP request */
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = iface->ip;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        icmp_hdr->icmp_type = 0; /* echo reply */
        icmp_hdr->icmp_sum = cksum(icmp_hdr, len - minLen);

        memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

        /*send echo reply*/
        sr_send_packet(sr, packet, len, interface);
      }
    }
    else
    { /* TCP/ UDP
       send icmp port unreachable */
      int sendLen = minLen + sizeof(sr_icmp_t3_hdr_t);
      uint8_t *sendPacket = (uint8_t *)malloc(sendLen);
      memset(sendPacket, 0, sendLen);

      sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(sendPacket + sizeof(sr_ethernet_hdr_t));
      sr_ethernet_hdr_t *send_eth_hdr = (sr_ethernet_hdr_t *)sendPacket;

      send_ip_hdr->ip_hl = ip_hdr->ip_hl;
      send_ip_hdr->ip_v = ip_hdr->ip_v;
      send_ip_hdr->ip_tos = ip_hdr->ip_tos;
      send_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
      send_ip_hdr->ip_id = ip_hdr->ip_id;
      send_ip_hdr->ip_off = ip_hdr->ip_off;
      send_ip_hdr->ip_ttl = 64;
      send_ip_hdr->ip_p = ip_protocol_icmp;
      send_ip_hdr->ip_sum = 0;
      send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));
      send_ip_hdr->ip_src = iface->ip;
      send_ip_hdr->ip_dst = ip_hdr->ip_src;

      memcpy(send_eth_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(send_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
      send_eth_hdr->ether_type = htons(ethertype_ip);

      sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(sendPacket + minLen);
      icmp_hdr->icmp_type = 3;
      icmp_hdr->icmp_code = 3;
      memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
      icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

      sr_send_packet(sr, sendPacket, sendLen, iface->name);
      free(sendPacket);
    }
  }
  else
  {
    /*For Elseplace
    check routing table
    check ARP Cache
    Miss: Send ARP request up to 5 time,
    Hit: send frame to next hope*/
    printf("Package is not for router\n");

    /*Decrease TTL and recalc checksum*/
    ip_hdr->ip_ttl -= 1;
    if (ip_hdr->ip_ttl == 0)
    {
      printf("TTL reached zero, Stop forwarding.\n");
      int sendLen = minLen + sizeof(sr_icmp_t3_hdr_t);
      uint8_t *sendPacket = (uint8_t *)malloc(sendLen);
      memset(sendPacket, 0, sendLen);

      sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(sendPacket + sizeof(sr_ethernet_hdr_t));
      sr_ethernet_hdr_t *send_eth_hdr = (sr_ethernet_hdr_t *)sendPacket;

      send_ip_hdr->ip_hl = ip_hdr->ip_hl;
      send_ip_hdr->ip_v = ip_hdr->ip_v;
      send_ip_hdr->ip_tos = ip_hdr->ip_tos;
      send_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
      send_ip_hdr->ip_id = ip_hdr->ip_id;
      send_ip_hdr->ip_off = ip_hdr->ip_off;
      send_ip_hdr->ip_ttl = 64;
      send_ip_hdr->ip_p = ip_protocol_icmp;
      send_ip_hdr->ip_sum = 0;
      send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));
      send_ip_hdr->ip_src = iface->ip;
      send_ip_hdr->ip_dst = ip_hdr->ip_src;

      memcpy(send_eth_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(send_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
      send_eth_hdr->ether_type = htons(ethertype_ip);

      sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(sendPacket + minLen);
      icmp_hdr->icmp_type = 11;
      icmp_hdr->icmp_code = 0;
      memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
      icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

      sr_send_packet(sr, sendPacket, sendLen, iface->name);
      free(sendPacket);
      return;
    }
    /*Recalc checksum, previous checksum is set to 0 when doing sanity check*/
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /*Check routing table, perform Longest Prefix Match*/
    struct sr_rt *routing_table = sr->routing_table;
    int max_len = 0;
    struct sr_rt *longest_prefix = NULL;
    int packet_dest_prefix = ip_hdr->ip_dst & routing_table->mask.s_addr;
    while (routing_table)
    {
      if (packet_dest_prefix == (routing_table->dest.s_addr && routing_table->mask.s_addr))
      {
        if (packet_dest_prefix > max_len)
        {
          max_len = packet_dest_prefix;
          longest_prefix = routing_table;
        }
      }
    }

    /*If no matching found, drop packet and send unreachable*/
    if (!longest_prefix)
    {
      int sendLen = minLen + sizeof(sr_icmp_t3_hdr_t);
      uint8_t *sendPacket = (uint8_t *)malloc(sendLen);
      memset(sendPacket, 0, sendLen);

      sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(sendPacket + sizeof(sr_ethernet_hdr_t));
      sr_ethernet_hdr_t *send_eth_hdr = (sr_ethernet_hdr_t *)sendPacket;

      send_ip_hdr->ip_hl = ip_hdr->ip_hl;
      send_ip_hdr->ip_v = ip_hdr->ip_v;
      send_ip_hdr->ip_tos = ip_hdr->ip_tos;
      send_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
      send_ip_hdr->ip_id = ip_hdr->ip_id;
      send_ip_hdr->ip_off = ip_hdr->ip_off;
      send_ip_hdr->ip_ttl = 64;
      send_ip_hdr->ip_p = ip_protocol_icmp;
      send_ip_hdr->ip_sum = 0;
      send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));
      send_ip_hdr->ip_src = iface->ip;
      send_ip_hdr->ip_dst = ip_hdr->ip_src;

      memcpy(send_eth_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(send_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
      send_eth_hdr->ether_type = htons(ethertype_ip);

      sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(sendPacket + minLen);
      icmp_hdr->icmp_type = 3;
      icmp_hdr->icmp_code = 0;
      memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
      icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

      sr_send_packet(sr, sendPacket, sendLen, iface->name);
      free(sendPacket);
      return;
    }

    /*Else, start forwarding packet to next hop ip*/
    /*First check if address in ARP cache using given function*/
    struct sr_arpentry *matched_arpcache = sr_arpcache_lookup(&sr->cache, longest_prefix->gw.s_addr);
    struct sr_if *longest_prefix_inf = sr_get_interface(sr, longest_prefix->interface);

    if (matched_arpcache)
    {
      /*Modify ethernet header's destination & soruce host*/
      /*Use next_hop_ip->mac mapping in entry to send the packet*/
      memcpy(e_hdr->ether_dhost, matched_arpcache->mac, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_shost, longest_prefix_inf->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, longest_prefix_inf->name);
      free(longest_prefix);
    }
    else
    {
      /* Not found. Send ARP request up to 5 times, works -> send packet, not -> send ICMP HOST unreachable */
      struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, longest_prefix->gw.s_addr, packet, len, longest_prefix_inf->name);
      handle_aqpreq(sr, arp_req);
    }
  }
}
