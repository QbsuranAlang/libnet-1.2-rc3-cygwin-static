/*
 *  $Id: libnet_link_win32.c,v 1.16 2004/02/18 18:19:00 mike Exp $
 *
 *  libnet
 *  libnet_link_win32.c - low-level win32 libwpcap routines
 *
 *  Copyright (c) 2001 - 2002 Don Bowman <don@sandvine.com>
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  Copyright (c) 2002 Roberto Larcher <roberto.larcher@libero.it>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/* MSVC warns about snprintf. This needs to be defined before the declaration of _snprintf is seen. */
#define _CRT_SECURE_NO_WARNINGS

/* Libnet's unnamespaced ICMP6_ macros stomp on the enumerated versions of
   these names in the MS headers, so pre-include this header. */

#define _WINSOCK2API_
//#include <winsock2.h>
//#include <iphlpapi.h> /* From the Microsoft Platform SDK */
#include <wtypes.h>
#include <sys/types.h>
//#include "common.h"
#include "bpf.h"
/*
*  Libnet generic protocol block memory object.  Sort of a poor man's mbuf.
*/
typedef int32_t libnet_ptag_t;
#define LIBNET_PTAG_INITIALIZER         0
struct libnet_protocol_block
{
	uint8_t *buf;                      /* protocol buffer */
	uint32_t b_len;                    /* length of buf */
	uint16_t h_len;                    /* header length */
									   /* Passed as last argument to libnet_do_checksum(). Not necessarily used
									   * by that function, it is essentially a pblock specific number, passed
									   * from _builder to the _do_checksum
									   *
									   * Unused for IPV4_H block types.
									   *
									   * For protocols that sit on top of IP, it should be the the amount of
									   * buf that will be included in the checksum, starting from the beginning
									   * of the header.
									   */
	uint32_t copied;                   /* bytes copied - the amount of data copied into buf */
									   /* Used and updated by libnet_pblock_append(). */
	uint8_t type;                      /* type of pblock */
									   /* this needs to be updated every time a new packet builder is added */
									   /* libnet_diag_dump_pblock_type() also needs updating for every new pblock tag */
#define LIBNET_PBLOCK_ARP_H             0x01    /* ARP header */
#define LIBNET_PBLOCK_DHCPV4_H          0x02    /* DHCP v4 header */
#define LIBNET_PBLOCK_DNSV4_H           0x03    /* DNS v4 header */
#define LIBNET_PBLOCK_ETH_H             0x04    /* Ethernet header */
#define LIBNET_PBLOCK_ICMPV4_H          0x05    /* ICMP v4 base header */
#define LIBNET_PBLOCK_ICMPV4_ECHO_H     0x06    /* ICMP v4 echo header */
#define LIBNET_PBLOCK_ICMPV4_MASK_H     0x07    /* ICMP v4 mask header */
#define LIBNET_PBLOCK_ICMPV4_UNREACH_H  0x08    /* ICMP v4 unreach header */
#define LIBNET_PBLOCK_ICMPV4_TIMXCEED_H 0x09    /* ICMP v4 exceed header */
#define LIBNET_PBLOCK_ICMPV4_REDIRECT_H 0x0a    /* ICMP v4 redirect header */
#define LIBNET_PBLOCK_ICMPV4_TS_H       0x0b    /* ICMP v4 timestamp header */
#define LIBNET_PBLOCK_IGMP_H            0x0c    /* IGMP header */
#define LIBNET_PBLOCK_IPV4_H            0x0d    /* IP v4 header */
#define LIBNET_PBLOCK_IPO_H             0x0e    /* IP v4 options */
#define LIBNET_PBLOCK_IPDATA            0x0f    /* IP data */
#define LIBNET_PBLOCK_OSPF_H            0x10    /* OSPF base header */
#define LIBNET_PBLOCK_OSPF_HELLO_H      0x11    /* OSPF hello header */
#define LIBNET_PBLOCK_OSPF_DBD_H        0x12    /* OSPF dbd header */
#define LIBNET_PBLOCK_OSPF_LSR_H        0x13    /* OSPF lsr header */
#define LIBNET_PBLOCK_OSPF_LSU_H        0x14    /* OSPF lsu header */
#define LIBNET_PBLOCK_OSPF_LSA_H        0x15    /* OSPF lsa header */
#define LIBNET_PBLOCK_OSPF_AUTH_H       0x16    /* OSPF auth header */
#define LIBNET_PBLOCK_OSPF_CKSUM        0x17    /* OSPF checksum header */
#define LIBNET_PBLOCK_LS_RTR_H          0x18    /* linkstate rtr header */
#define LIBNET_PBLOCK_LS_NET_H          0x19    /* linkstate net header */
#define LIBNET_PBLOCK_LS_SUM_H          0x1a    /* linkstate as sum header */
#define LIBNET_PBLOCK_LS_AS_EXT_H       0x1b    /* linkstate as ext header */
#define LIBNET_PBLOCK_NTP_H             0x1c    /* NTP header */
#define LIBNET_PBLOCK_RIP_H             0x1d    /* RIP header */
#define LIBNET_PBLOCK_TCP_H             0x1e    /* TCP header */
#define LIBNET_PBLOCK_TCPO_H            0x1f    /* TCP options */
#define LIBNET_PBLOCK_TCPDATA           0x20    /* TCP data */
#define LIBNET_PBLOCK_UDP_H             0x21    /* UDP header */
#define LIBNET_PBLOCK_VRRP_H            0x22    /* VRRP header */
#define LIBNET_PBLOCK_DATA_H            0x23    /* generic data */
#define LIBNET_PBLOCK_CDP_H             0x24    /* CDP header */
#define LIBNET_PBLOCK_IPSEC_ESP_HDR_H   0x25    /* IPSEC ESP header */
#define LIBNET_PBLOCK_IPSEC_ESP_FTR_H   0x26    /* IPSEC ESP footer */
#define LIBNET_PBLOCK_IPSEC_AH_H        0x27    /* IPSEC AH header */
#define LIBNET_PBLOCK_802_1Q_H          0x28    /* 802.1q header */
#define LIBNET_PBLOCK_802_2_H           0x29    /* 802.2 header */
#define LIBNET_PBLOCK_802_2SNAP_H       0x2a    /* 802.2 SNAP header */
#define LIBNET_PBLOCK_802_3_H           0x2b    /* 802.3 header */
#define LIBNET_PBLOCK_STP_CONF_H        0x2c    /* STP configuration header */
#define LIBNET_PBLOCK_STP_TCN_H         0x2d    /* STP TCN header */
#define LIBNET_PBLOCK_ISL_H             0x2e    /* ISL header */
#define LIBNET_PBLOCK_IPV6_H            0x2f    /* IP v6 header */
#define LIBNET_PBLOCK_802_1X_H          0x30    /* 802.1x header */
#define LIBNET_PBLOCK_RPC_CALL_H        0x31    /* RPC Call header */
#define LIBNET_PBLOCK_MPLS_H            0x32    /* MPLS header */
#define LIBNET_PBLOCK_FDDI_H            0x33    /* FDDI header */
#define LIBNET_PBLOCK_TOKEN_RING_H      0x34    /* TOKEN RING header */
#define LIBNET_PBLOCK_BGP4_HEADER_H     0x35    /* BGP4 header */
#define LIBNET_PBLOCK_BGP4_OPEN_H       0x36    /* BGP4 open header */
#define LIBNET_PBLOCK_BGP4_UPDATE_H     0x37    /* BGP4 update header */
#define LIBNET_PBLOCK_BGP4_NOTIFICATION_H 0x38  /* BGP4 notification header */
#define LIBNET_PBLOCK_GRE_H             0x39    /* GRE header */
#define LIBNET_PBLOCK_GRE_SRE_H         0x3a    /* GRE SRE header */
#define LIBNET_PBLOCK_IPV6_FRAG_H       0x3b    /* IPv6 frag header */
#define LIBNET_PBLOCK_IPV6_ROUTING_H    0x3c    /* IPv6 routing header */
#define LIBNET_PBLOCK_IPV6_DESTOPTS_H   0x3d    /* IPv6 dest opts header */
#define LIBNET_PBLOCK_IPV6_HBHOPTS_H    0x3e    /* IPv6 hop/hop opts header */
#define LIBNET_PBLOCK_SEBEK_H           0x3f    /* Sebek header */
#define LIBNET_PBLOCK_HSRP_H            0x40    /* HSRP header */
#define LIBNET_PBLOCK_ICMPV6_H          0x41    /* ICMPv6 header (unused) */
#define LIBNET_PBLOCK_ICMPV6_ECHO_H     0x46    /* ICMPv6 echo header */
#define LIBNET_PBLOCK_ICMPV6_UNREACH_H  0x42    /* ICMPv6 unreach header */
#define LIBNET_PBLOCK_ICMPV6_NDP_NSOL_H 0x43    /* ICMPv6 NDP neighbor solicitation header */
#define LIBNET_PBLOCK_ICMPV6_NDP_NADV_H 0x44    /* ICMPv6 NDP neighbor advertisement header */
#define LIBNET_PBLOCK_ICMPV6_NDP_OPT_H  0x45    /* ICMPv6 NDP option */

	uint8_t flags;                             /* control flags */
#define LIBNET_PBLOCK_DO_CHECKSUM       0x01    /* needs a checksum */
	libnet_ptag_t ptag;                 /* protocol block tag */
										/* Chains are built from highest level protocol, towards the link level, so
										* prev traverses away from link level, and next traverses towards the
										* link level.
										*/
	struct libnet_protocol_block *next; /* next pblock */
	struct libnet_protocol_block *prev; /* prev pblock */
};
typedef struct libnet_protocol_block libnet_pblock_t;
struct libnet_context
{
	SOCKET fd;
	LPADAPTER  lpAdapter;
	int injection_type;                 /* one of: */
#define LIBNET_NONE     0xf8            /* no injection type, only construct packets */
#define LIBNET_LINK     0x00            /* link-layer interface */
#define LIBNET_RAW4     0x01            /* raw socket interface (ipv4) */
#define LIBNET_RAW6     0x02            /* raw socket interface (ipv6) */
										/* the following should actually set a flag in the flags variable above */
#define LIBNET_LINK_ADV 0x08            /* advanced mode link-layer */
#define LIBNET_RAW4_ADV 0x09            /* advanced mode raw socket (ipv4) */
#define LIBNET_RAW6_ADV 0x0a            /* advanced mode raw socket (ipv6) */
#define LIBNET_ADV_MASK 0x08            /* mask to determine adv mode */

										/* _blocks is the highest level, and _end is closest to link-level */
	libnet_pblock_t *protocol_blocks;   /* protocol headers / data */
	libnet_pblock_t *pblock_end;        /* last node in list */
	uint32_t n_pblocks;                /* number of pblocks */

	int link_type;                      /* link-layer type, a DLT_ value. */
										/* These are the only values used by libnet (see libnet_build_arp and
										* libnet_build_link).  Other values are assigned by the various
										* libnet_link_*.c OS support functions, but are not yet used or supported,
										* they are effectively dead code. <pcap.h> claims these two are invariant
										* across operating systems... hopefully it is correct!
										*/
#ifndef DLT_EN10MB
# define DLT_EN10MB      1       /* Ethernet (10Mb) */
#endif
#ifndef DLT_IEEE802
# define DLT_IEEE802     6       /* IEEE 802 Networks */
#endif

	int link_offset;                    /* link-layer header size */
	int aligner;                        /* used to align packets */
	char *device;                       /* device name */

	struct libnet_stats stats;          /* statistics */
	libnet_ptag_t ptag_state;           /* state holder for pblock tag */
	char label[LIBNET_LABEL_SIZE];      /* textual label for cq interface */

	char err_buf[LIBNET_ERRBUF_SIZE];   /* error buffer */
	uint32_t total_size;               /* total size */
};
typedef struct libnet_context libnet_t;

//#include <winsock2.h>
//#include <assert.h>
//#include <Packet32.h>
//#include <Ntddndis.h>
//#include "iprtrmib.h"

int
libnet_open_link(libnet_t *l)
{
    DWORD dwErrorCode;
    NetType IFType;

    if (l == NULL)
    { 
        return (-1);
    } 

    if (l->device == NULL)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): NULL device", __func__);
        return (-1);
    }

    l->lpAdapter = 0;

    /* open adapter */
	l->lpAdapter = PacketOpenAdapter(l->device);
    if (!l->lpAdapter || (l->lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        dwErrorCode=GetLastError();
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): unable to open the driver, error Code : %lx",
                __func__, dwErrorCode); 
        return (-1);
    }
	
    /* increase the send buffer */
    PacketSetBuff(l->lpAdapter, 512000);

    /*
     *  Assign link type and offset.
     */
    if (PacketGetNetType(l->lpAdapter, &IFType))
    {
        switch(IFType.LinkType)
        {
            case NdisMedium802_3:
				l->link_type = DLT_EN10MB;
				l->link_offset = LIBNET_ETH_H;
                break;
			case NdisMedium802_5:
				l->link_type = DLT_IEEE802;
				l->link_offset = LIBNET_TOKEN_RING_H;
				break;
			case NdisMediumFddi:
				l->link_type = DLT_FDDI;
				l->link_offset = 0x15;
				break;
			case NdisMediumWan:
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                 "%s():, WinPcap has disabled support for Network type (%d)",
                 __func__, IFType.LinkType);
				return (-1);
				break;
			case NdisMediumAtm:
				l->link_type = DLT_ATM_RFC1483;
				break;
			case NdisMediumArcnet878_2:
				l->link_type = DLT_ARCNET;
				break;
			default:
                snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                         "%s(): network type (%d) is not supported",
                         __func__, IFType.LinkType);
                return (-1);
                break;
        }
    }
    else
    {
        dwErrorCode=GetLastError();
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "%s(): unable to determine the network type, error Code : %lx",
                __func__, dwErrorCode);
        return (-1);
    }
    return (1);
}

int
libnet_close_link_interface(libnet_t *l)
{
    if (l->lpAdapter)
    {
        PacketSetHwFilter(l->lpAdapter, NDIS_PACKET_TYPE_ALL_LOCAL);
        PacketCloseAdapter(l->lpAdapter);
    }
    return (1);
}

int
libnet_write_link(libnet_t *l, const uint8_t *packet, uint32_t size)
{
    LPPACKET   lpPacket;
    DWORD      BytesTransfered;	

    BytesTransfered = -1;

    if ((lpPacket = PacketAllocatePacket()) == NULL)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): failed to allocate the LPPACKET structure", __func__);
        return (-1);
    }
    /* FIXME Packet* arguments aren't const, are they actually modified? That would be a problem, we can't modify our input */
    PacketInitPacket(lpPacket, packet, size);

    /* PacketSendPacket returns a BOOLEAN */
    if(PacketSendPacket(l->lpAdapter, lpPacket, TRUE))
    {
	    BytesTransfered = size;
    }
	
    PacketFreePacket(lpPacket);
    return (BytesTransfered);
 }

struct libnet_ether_addr *
libnet_get_hwaddr(libnet_t *l)
{
    /* This implementation is not-reentrant. */
    static struct libnet_ether_addr *mac;
    
    ULONG IoCtlBufferLength = (sizeof(PACKET_OID_DATA) + sizeof(ULONG) - 1);
	PPACKET_OID_DATA OidData;
	
	int i = 0;

	if (l == NULL)
    { 
        return (NULL);
    } 

	if (l->device == NULL)
    {           
        if (libnet_select_device(l) == -1)
        {   
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                    "%s(): can't figure out a device to use", __func__);
            return (NULL);
        }
    }

    mac = (struct libnet_ether_addr *)calloc(1,sizeof(struct libnet_ether_addr));
	if (mac == NULL)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                    "%s(): calloc error", __func__);
		return (NULL);
	}

    OidData = (struct _PACKET_OID_DATA *) malloc(IoCtlBufferLength);
	
	if (OidData == NULL)
	{
	     snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				 "%s(): OidData is NULL", __func__);
	    return(NULL);
	}

	if (l->link_type == DLT_IEEE802)
	{
		OidData->Oid = OID_802_5_CURRENT_ADDRESS;	
	}
	else
	{
		OidData->Oid = OID_802_3_CURRENT_ADDRESS;	
	}
	
	OidData->Length = 6;
	if((PacketRequest(l->lpAdapter, FALSE, OidData)) == FALSE)
	{
		memset(mac, 0, 6);
	}
	else
	{
		for (i = 0; i < 6; i++)
		{
			mac->ether_addr_octet[i] = OidData->Data[i];
		}
	}
    free(OidData);
    return(mac);
}


BYTE *
libnet_win32_get_remote_mac(libnet_t *l, DWORD DestIP)
{
	HRESULT hr;
    ULONG   pulMac[6];
    ULONG   ulLen = 6;
	static PBYTE pbHexMac;
	PIP_ADAPTER_INFO pinfo = NULL;
	DWORD dwSize = 0;
	struct sockaddr_in sin;
	static BYTE bcastmac[]= {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

	BYTE *MAC = libnet_win32_read_arp_table(DestIP);
	
	if (MAC==NULL)
	{
		memset(pulMac, 0xff, sizeof (pulMac));
		memset(&sin, 0, sizeof(sin));
	    
		if((hr = SendARP (DestIP, 0, pulMac, &ulLen)) != NO_ERROR)
		{
			*(int32_t *)&sin.sin_addr = DestIP;
			GetAdaptersInfo(NULL, &dwSize);
			pinfo = (PIP_ADAPTER_INFO)GlobalAlloc(GPTR, dwSize);
			GetAdaptersInfo(pinfo, &dwSize);
			if(pinfo != NULL)
			{
				DestIP = inet_addr(pinfo->GatewayList.IpAddress.String);
				memset (pulMac, 0xff, sizeof (pulMac));
				ulLen = 6;
				if((hr = SendARP (DestIP, 0, pulMac, &ulLen)) != NO_ERROR)
				{
					GlobalFree(pinfo);
					return(bcastmac);
				}
			}
			else
			{
				GlobalFree(pinfo);
				return(bcastmac); /* ff:ff:ff:ff:ff:ff */
			}
		}
	  	
		pbHexMac = (PBYTE) pulMac;

		return (pbHexMac);
	}
	else
	{
		return (MAC);
	}
}

BYTE * libnet_win32_read_arp_table(DWORD DestIP)
{
	static BYTE buffMAC[6];
    BOOL fOrder=TRUE;
	BYTE *MAC=NULL;
	DWORD status, i, ci;
    
    PMIB_IPNETTABLE pIpNetTable = NULL;
	DWORD Size = 0;
	
	memset(buffMAC, 0, sizeof(buffMAC));

    if((status = GetIpNetTable(pIpNetTable, &Size, fOrder)) == ERROR_INSUFFICIENT_BUFFER)
    {
        pIpNetTable = (PMIB_IPNETTABLE) malloc(Size);
        assert(pIpNetTable);        
        status = GetIpNetTable(pIpNetTable, &Size, fOrder);
    }

	if(status == NO_ERROR)
	{
		/* set current interface */
		ci = pIpNetTable->table[0].dwIndex;

		for (i = 0; i < pIpNetTable->dwNumEntries; ++i)
		{
			if (pIpNetTable->table[i].dwIndex != ci)
			    ci = pIpNetTable->table[i].dwIndex;

			if(pIpNetTable->table[i].dwAddr == DestIP) /* found IP in arp cache */
			{
				memcpy(buffMAC, pIpNetTable->table[i].bPhysAddr, sizeof(buffMAC));
				free(pIpNetTable);
				return buffMAC;
			}        
		}
		  
		if (pIpNetTable)
            free (pIpNetTable);
		return(NULL);
	}
    else
    {
        if (pIpNetTable)
        {
            free (pIpNetTable);
        }
        MAC=NULL;
    }
    return(NULL);
}

/* EOF */
