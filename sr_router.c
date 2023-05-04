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
  printf("ARP Packet: \n");
  print_hdrs(packet, len);
  printf("----------------\n");

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
    printf("ARP packet is requesting for reply\n");
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
    printf("Reply has been sent to the ARP request\n");
    sr_send_packet(sr, reply_packet, len, interface);
    printf("Reply Packet: \n");
    print_hdrs(reply_packet, len);
    printf("----------------\n");
    free(reply_packet);
  }

  /* ARP packet is a reply with information of the sender to the current interface */
  else if (arp_op_reply == ntohs(received_arp_hdr->ar_op))
  {
    printf("ARP packet is reply from sent request\n");
    /* The implemented algorithm is from line 39-47 from sr_arpache.h:

    The ARP reply processing code should move entries from the ARP request
    queue to the ARP cache:

    # When servicing an arp reply that gives us an IP->MAC mapping
    req = arpcache_insert(ip, mac)

    if req:
      send all packets on the req->packets linked list
      arpreq_destroy(req) */
    
    struct sr_arpcache *cache = &sr->cache;
    unsigned char *mac = received_arp_hdr->ar_sha;
    uint32_t ip = received_arp_hdr->ar_sip;
    struct sr_arpreq *req = sr_arpcache_insert(cache, mac, ip);

    /* Succesfully found this IP in the request queue*/
    if (req)
    {
      printf("Reply has been inserted into cache\n");
      struct sr_packet *waiting_packet = req->packets;
      /*Send all packets waiting for the request to finish*/
      while (waiting_packet)
      {
        printf("Waiting Packet: \n");
        print_hdrs(waiting_packet->buf, waiting_packet->len);
        printf("----------------\n");
        struct sr_if *waiting_iface = sr_get_interface(sr, waiting_packet->iface);
        /*Initialize header for the raw ethernet frame of the waiting packet*/
        sr_ethernet_hdr_t *waiting_ether_hdr = (sr_ethernet_hdr_t *)waiting_packet->buf;
        /* the source address is the address of waiting packet's interface */
        memcpy(waiting_ether_hdr->ether_shost, waiting_iface->addr, ETHER_ADDR_LEN);
        /* the destination address is the source address of received packet */
        memcpy(waiting_ether_hdr->ether_dhost, received_arp_hdr->ar_sha, ETHER_ADDR_LEN);

        /* Send the waiting packet to the sender and set to the next packet until NULL*/
        sr_send_packet(sr, waiting_packet->buf, waiting_packet->len, waiting_packet->iface);
        printf("Sent waiting packet to the sender\n");
        printf("Waiting Packet Sent: \n");
        print_hdrs(waiting_packet->buf, waiting_packet->len);
        printf("----------------\n");
        waiting_packet = waiting_packet->next;
      }
      /* Free all memory associated with this arp request entry*/
      sr_arpreq_destroy(cache, req);
    }
    else
    {
      printf("FAILED to find the IP in cache, added IP to cache\n");
    }
  }
}

int is_for_me(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr)
{
  int result = 0;
  struct sr_if *iface = sr->if_list;

  printf("Checking if IP packet matches one of the interfaces of the router \n");
  printf("Looking for IP:\n");
  print_addr_ip_int(ntohl(ip_hdr->ip_dst));
  while (iface)
  {
    printf("Found for IP:\n");
    print_addr_ip_int(ntohl(iface->ip));
    if (iface->ip == ip_hdr->ip_dst)
    {
      printf("Found!! \n");
      result = 1;
      break;
    }
    iface = iface->next;
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

  printf("In handle_ip: \n");
  print_hdrs(packet, len);
  printf("----------------\n");

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

  /* Packet is sent to one of your router’s IP addresses */
  if (is_for_me(sr, ip_hdr))
  {
    printf("Package is FOR router\n");
    /* Packet is ICMP*/
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
      uint16_t received_icmp_checksum = icmp_hdr->icmp_sum;
      icmp_hdr->icmp_sum = 0;
      uint16_t icmp_checksum = cksum(icmp_hdr, len - minLen);
      if (icmp_checksum != received_icmp_checksum)
      {
        fprintf(stderr, "Error: Packet has incorrect checksum??\n");
        return;
      }

      /* ICMP echo request -> Send ICMP echo reply */
      if (icmp_hdr->icmp_type == 8)
      {
        printf("Packet is echo request!! \n");
        send_icmp(sr, packet, len, iface, 0, 0);
      }
    }
    else
    { /* if TCP/ UDP send icmp port unreachable
        otherwise ignore*/
      send_icmp(sr, packet, len, iface, 3, 3);
    }
  }
  else
  {
    /*For Elseplace
    check routing table
    check ARP Cache
    Miss: Send ARP request up to 5 time,
    Hit: send frame to next hope*/
    printf("Package is NOT FOR router\n");

    /*Decrease TTL and recalc checksum*/
    ip_hdr->ip_ttl -= 1;
    if (ip_hdr->ip_ttl == 0)
    {
      printf("TTL reached zero, Stop forwarding.\n");
      send_icmp(sr, packet, len, iface, 11, 0);
      return;
    }
    /*Recalc checksum, previous checksum is set to 0 when doing sanity check*/
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Check routing table, perform Longest Prefix Match */
    printf("Call longest_prefix_match - handle ip \n");
    struct sr_rt *longest_prefix = longest_prefix_match(sr, ip_hdr->ip_dst);
    printf("Returned from longest_prefix_match - handle ip \n");
    /*     printf("longest_prefix interface: %s \n", longest_prefix->interface);
        printf("longest_prefix gateway ip:\n");
        print_addr_ip_int(ntohl(longest_prefix->gw.s_addr)); */

    /*If no matching found, drop packet and send unreachable*/
    if (!longest_prefix)
    {
      printf("No match in routing table - handle ip \n");
      send_icmp(sr, packet, len, iface, 3, 0);
      return;
    }

    printf("Match found in routing table - handle ip \n");

    /*Else, start forwarding packet to next hop ip*/
    /*First check if address in ARP cache using given function*/
    struct sr_arpentry *matched_arpcache = sr_arpcache_lookup(&sr->cache, longest_prefix->gw.s_addr);
    struct sr_if *longest_prefix_inf = sr_get_interface(sr, longest_prefix->interface);

    printf("Checking if address in ARP Cache - handle ip \n");

    if (matched_arpcache)
    {
      /*Modify ethernet header's destination & soruce host*/
      /*Use next_hop_ip->mac mapping in entry to send the packet*/
      printf("Address is IN ARP Cache - handle ip \n");
      memcpy(e_hdr->ether_dhost, matched_arpcache->mac, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_shost, longest_prefix_inf->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, longest_prefix_inf->name);
      printf("Packet sent to next hop - handle ip \n");
    }
    else
    {
      printf("Address is NOT IN ARP Cache - handle ip \n");
      /* Not found. Send ARP request up to 5 times, works -> send packet, not -> send ICMP HOST unreachable */
      struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, longest_prefix->gw.s_addr, packet, len, longest_prefix_inf->name);
      printf("Address is queued in ARP Cache - handle ip \n");
      handle_arpreq(sr, arp_req);
    }
  }
}

/* Send ICMP packet to input packet's source */
void send_icmp(struct sr_instance *sr,
               uint8_t *packet,
               unsigned int len,
               struct sr_if *incoming_interface,
               uint8_t type,
               uint8_t code)
{
  printf("Sending ICMP message \n");

  /* Initialize headers for input packet*/
  struct sr_arpcache *cache = &sr->cache;
  sr_ethernet_hdr_t *input_ether_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *input_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Find routing table entry with longest prefix match with the destination IP address,
  such entry is the outgoing interface */
  printf("In send_icmp, input packet: \n");
  print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
  printf("----------------\n");

  struct sr_rt *rt_entry = longest_prefix_match(sr, input_ip_hdr->ip_src);
  if (!rt_entry)
  {
    fprintf(stderr, "Error: IP has no match in the router's rounting table.\n");
    return;
  }
  struct sr_if *outgoing_interface = sr_get_interface(sr, rt_entry->interface);

  /* Echo reply */
  if (type == 0)
  {
    printf("Sending Echo Reply \n");
    int icmp_len = len;
    uint8_t *icmp_packet = (uint8_t *)malloc(icmp_len);
    memcpy(icmp_packet, packet, icmp_len);

    /* Initialize header for the raw ethernet frame of icmp packet*/
    sr_ethernet_hdr_t *icmp_ether_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    /* the source is input packet's interface, and the destination is input packet's source */
    memcpy(icmp_ether_hdr->ether_shost, incoming_interface->addr, ETHER_ADDR_LEN);
    memcpy(icmp_ether_hdr->ether_dhost, input_ether_hdr->ether_shost, ETHER_ADDR_LEN);

    /* Initialize header for the ip frame of icmp packet*/
    sr_ip_hdr_t *icmp_ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    /* source is from router */
    icmp_ip_hdr->ip_src = input_ip_hdr->ip_dst;
    icmp_ip_hdr->ip_dst = input_ip_hdr->ip_src;
    icmp_ip_hdr->ip_sum = 0;
    icmp_ip_hdr->ip_sum = cksum(icmp_ip_hdr, sizeof(sr_ip_hdr_t));

    /* Initialize header for the icmp frame of icmp packet*/
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    printf("In send_icmp, icmp type 0 packet: \n");
    print_hdrs(icmp_packet, icmp_len);
    printf("----------------\n");

    /* check the ARP cache for the corresponding MAC address  */
    struct sr_arpentry *in_cache = sr_arpcache_lookup(cache, rt_entry->gw.s_addr);
    /* If there is send, else send an ARP request for the next-hop IP, and add the packet to the queue of packets waiting on this ARP request.*/
    if (in_cache)
    {
      printf("Found in cache, sending packet \n");
      sr_send_packet(sr, icmp_packet, icmp_len, outgoing_interface->name);
    }
    else
    {
      printf("NOT in cache sending ARP request \n");
      struct sr_arpreq *req = sr_arpcache_queuereq(cache, rt_entry->gw.s_addr, icmp_packet, icmp_len, outgoing_interface->name);
      handle_arpreq(sr, req);
    }
    free(icmp_packet);
  }

  /* Rest of the ICMP messages */
  else
  {
    int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = (uint8_t *)malloc(icmp_len);
    memcpy(icmp_packet, packet, icmp_len);

    /* Initialize header for the raw ethernet frame of icmp packet*/
    sr_ethernet_hdr_t *icmp_ether_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    /* the source is waiting packet's destination, and the destination is waiting packet's source */
    memcpy(icmp_ether_hdr->ether_shost, incoming_interface->addr, ETHER_ADDR_LEN);
    memcpy(icmp_ether_hdr->ether_dhost, input_ether_hdr->ether_shost, ETHER_ADDR_LEN);
    icmp_ether_hdr->ether_type = htons(ethertype_ip);

    /* Initialize header for the ip frame of icmp packet*/
    sr_ip_hdr_t *icmp_ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    icmp_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    icmp_ip_hdr->ip_ttl = INIT_TTL;
    icmp_ip_hdr->ip_p = ip_protocol_icmp;

    if (code == 3)
    {
      icmp_ip_hdr->ip_src = input_ip_hdr->ip_dst;
    }
    else
    {
      icmp_ip_hdr->ip_src = incoming_interface->ip;
    }

    icmp_ip_hdr->ip_dst = input_ip_hdr->ip_src;
    icmp_ip_hdr->ip_sum = 0;
    icmp_ip_hdr->ip_sum = cksum(icmp_ip_hdr, sizeof(sr_ip_hdr_t));

    /* Initialize header for the icmp frame of icmp packet*/
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    icmp_hdr->icmp_sum = 0;
    memcpy(icmp_hdr->data, input_ip_hdr, ICMP_DATA_SIZE);
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    printf("In send_icmp, icmp type 3 packet: \n");
    print_hdrs(icmp_packet, icmp_len);
    printf("----------------\n");

    /* check the ARP cache for the corresponding MAC address  */
    struct sr_arpentry *in_cache = sr_arpcache_lookup(cache, rt_entry->gw.s_addr);
    /* If there is send, else send an ARP request for the next-hop IP, and add the packet to the queue of packets waiting on this ARP request.*/
    if (in_cache)
    {
      printf("Found in cache, sending packet \n");
      sr_send_packet(sr, icmp_packet, icmp_len, outgoing_interface->name);
    }
    else
    {
      printf("NOT in cache sending ARP request \n");
      struct sr_arpreq *req = sr_arpcache_queuereq(cache, rt_entry->gw.s_addr, icmp_packet, icmp_len, outgoing_interface->name);
      handle_arpreq(sr, req);
    }
    free(icmp_packet);
  }
}

struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ip)
{
  struct sr_rt *routing_table = sr->routing_table;
  struct sr_rt *longest_entry = NULL;
  int packet_dest_prefix = ip & routing_table->mask.s_addr;

  printf("Finding longest matching prefix entry for: \n");
  print_addr_ip_int(ntohl(ip));
  while (routing_table)
  {
    if (packet_dest_prefix == (routing_table->dest.s_addr & routing_table->mask.s_addr))
    {
      if (!longest_entry)
      {
        printf("Matching prefix found \n");
        longest_entry = routing_table;
      }

      else if (longest_entry && (routing_table->mask.s_addr > longest_entry->mask.s_addr))
      {
        printf("Longest prefix entry updated to longer value\n");
        longest_entry = routing_table;
      }
    }
    routing_table = routing_table->next;
  }
  return longest_entry;
}
