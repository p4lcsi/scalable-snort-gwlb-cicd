#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <daq_module_api.h>
#include <daq_dlt.h>

#define gwlb_err(ctx, ...)              api.set_errbuf(ctx->inst, __VA_ARGS__)

#define MIN_POOL_SZ                     32
#define GWLB_VERSION                    1
#define MIN(a, b)                       ((a) < (b) ? (a) : (b))

#define DAQ_PKT_META_FLOW_DESC          (DAQ_PKT_META_DECODE_DATA + 1)

/* For parsing packets.. */
struct vlan_header {
    uint16_t                    tpid;
    uint16_t                    ether_type;
};

/* Structure for a NIC device */
typedef struct _nic {
    int                         sock;
} nic_t;

/* Structure of a  DAQ packet */
typedef struct _pktdesc {
    DAQ_Msg_t                   msg;
    DAQ_PktHdr_t                hdr;
    uint8_t                     *data;
    int                         pktlen;
    int                         ifidx;
    struct _pktdesc             *next;
} pktdesc_t;

/* Structure for packet pool */
typedef struct _pktpool {
    pktdesc_t                   *pool;
    pktdesc_t                   *flist;
    uint8_t                     *dbuf;
    DAQ_MsgPoolInfo_t           info;
} pktpool_t;

/* Context for an instance of this DAQ */
typedef struct _context {
    char                        *input;
    nic_t                       *nic;

    DAQ_Mode                    mode;
    DAQ_ModuleInstance_h        inst;
    DAQ_Stats_t                 stats;
    pktpool_t                   pool;
    unsigned                    snap;
    bool                        intr;
    int                         wtime;
} context_t;

static DAQ_BaseAPI_t            api;
static int gwlb_dlt(void *handle);

/*
 * nic_open
 * Get a descriptor to work with packet device
 */
static nic_t *nic_open (char *name)
{
    struct sockaddr_ll          addr;
    nic_t                       *nic;
    int                         sock;
    int                         ifidx;
    int                         val;

    printf("NicOpen %s\n", name);
    nic     =   calloc(1, sizeof(nic_t));
    if (nic == NULL) {
        return (NULL);
    }

    ifidx   =   if_nametoindex(name);
    if (ifidx == 0) {
        free(nic);
        return (NULL);
    }

    sock    =   socket(PF_PACKET, (SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC), htons(ETH_P_ALL));
    if (sock < 0) {
        free(nic);
        return (NULL);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sll_family     =   AF_PACKET;
    addr.sll_protocol   =   htons(ETH_P_ALL);
    addr.sll_ifindex    =   ifidx;

    if (bind(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_ll)) < 0) {
        close(sock);
        free(nic);
        return (NULL);
    }

    val     =   (PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG) << 16 | ifidx;
    if (setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &val, sizeof(int)) < 0) {
        close(sock);
        free(nic);
        return (NULL);
    }

    nic->sock   =   sock;

    return (nic);
}

/*
 * nic_close
 * Release NIC related resources
 */
static void nic_close (nic_t *nic)
{
    if (nic) {
        close(nic->sock);
        free(nic);
    }
}

/*
 * nic_read
 * Read a packet from network interface
 */
static int nic_read (nic_t *nic, uint8_t *buf, int maxlen)
{
    int                         nread;

    nread       =   read(nic->sock, buf, maxlen);
    if (nread < 0) {
        if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
            return (0);
        }

        return (-1);
    }

    return (nread);
}

/*
 * nic_write
 * Send a packet out
 */
static int nic_write (nic_t *nic, uint8_t *data, int pktlen)
{
    return (write(nic->sock, data, pktlen));
}

/*
 * is_vlan_type
 * Return non-zero if given ether type is for a VLAN
 */
static int is_vlan_type (uint16_t et)
{
    int                         ret;

    switch (et) {
    case    ETH_P_8021Q:
    case    ETH_P_QINQ1:
    case    ETH_P_QINQ2:
    case    ETH_P_QINQ3:
        ret     =   true;
        break;

    default:
        ret     =   false;
        break;
    }

    return (ret);
}

/*
 * swap_l2_addr
 * Swap L2 DA and SA
 */
static void swap_l2_addr (uint8_t *data)
{
    struct ether_header         *eth;
    uint8_t                     *da;
    uint8_t                     *sa;
    uint8_t                     tmp;
    int                         idx;

    eth     =   (struct ether_header *) data;
    da      =   eth->ether_dhost;
    sa      =   eth->ether_shost;

    for (idx = 0; idx < ETH_ALEN; idx++) {
        tmp     =   *da;
        *da++   =   *sa;
        *sa++   =   tmp;
    }
}

/*
 * swap_ipv4
 * Swap IPv4 da & sa
 */
static void swap_ipv4 (struct iphdr *hdr)
{
    uint32_t                    tmp;

    tmp         =   hdr->daddr;
    hdr->daddr  =   hdr->saddr;
    hdr->saddr  =   tmp;
}

/*
 * swap_ipv6
 * Swap addresses in IPv6 header
 */
static void swap_ipv6 (struct ip6_hdr *hdr)
{
    struct in6_addr             tmp;

    tmp             =   hdr->ip6_dst;
    hdr->ip6_dst    =   hdr->ip6_src;
    hdr->ip6_src    =   tmp;
}

/*
 * swap_l3_addr
 * Swap outer L3 address
 */
static void swap_l3_addr (uint8_t *data)
{
    struct ether_header         *eth;
    struct vlan_header          *vhdr;
    uint8_t                     *ptr;
    uint16_t                    et;

    ptr     =   data;

    eth     =   (struct ether_header *) ptr;
    ptr    +=   sizeof(struct ether_header);

    et      =   ntohs(eth->ether_type);

    while (is_vlan_type(et)) {
        vhdr    =   (struct vlan_header *)ptr;
        ptr    +=   sizeof(struct vlan_header);

        et      =   ntohs(vhdr->ether_type);
    }

    if (et == ETH_P_IP) {
        swap_ipv4((struct iphdr *) ptr);
    } else if (et == ETH_P_IPV6) {
        swap_ipv6((struct ip6_hdr *) ptr);
    }
}

/*
 * init_daq_msg
 * Initialize a DAQ Message structure
 */
static void init_daq_msg (context_t *ctx, pktdesc_t *desc)
{
    DAQ_Msg_t                   *msg;

    msg             =   &desc->msg;

    msg->type       =   DAQ_MSG_TYPE_PACKET;
    msg->hdr_len    =   sizeof(DAQ_PktHdr_t);
    msg->hdr        =   &desc->hdr;
    msg->data       =   desc->data;
    msg->owner      =   ctx->inst;
    msg->priv       =   desc;
}

/*
 * init_daq_hdr
 * Initialize a DAQ Packet Header structure
 */
static void init_daq_hdr (context_t *ctx, pktdesc_t *desc)
{
    DAQ_PktHdr_t                *hdr;

    hdr                     =   &desc->hdr;
    hdr->ingress_index      =   DAQ_PKTHDR_UNKNOWN;
    hdr->egress_index       =   DAQ_PKTHDR_UNKNOWN;
    hdr->ingress_group      =   DAQ_PKTHDR_UNKNOWN;
    hdr->egress_group       =   DAQ_PKTHDR_UNKNOWN;
}

/*
 * gwlb_getdesc
 * Get a descriptor from the pool
 */
static pktdesc_t *gwlb_getdesc (context_t *ctx)
{
    pktpool_t                   *pool;
    pktdesc_t                   *desc;

    pool    =   &ctx->pool;
    desc    =   pool->flist;
    if (desc == NULL) {
        return (NULL);
    }

    pool->flist    =   desc->next;
    desc->next     =   NULL;
    pool->info.available--;

    return (desc);
}

/*
 * gwlb_putdesc
 * Return a descriptor to pool's freelist
 */
static void gwlb_putdesc (context_t *ctx, pktdesc_t *desc)
{
    pktpool_t                   *pool;

    pool    =   &ctx->pool;

    desc->next  =   pool->flist;
    pool->flist =   desc;
    pool->info.available++;
}

/*
 * gwlb_mkpool
 * Allocate resources for packet pool
 */
static int gwlb_mkpool (context_t *ctx, unsigned nbuf)
{
    pktpool_t                   *pool;
    pktdesc_t                   *desc;
    uint8_t                     *pptr;
    int                         idx;

    pool        =   &ctx->pool;
    pool->pool  =   calloc(nbuf, sizeof(pktdesc_t));
    if (pool->pool == NULL) {
        gwlb_err(ctx, "Cannot allocate %zd bytes\n", (nbuf * sizeof(pktdesc_t)));
        return (DAQ_ERROR_NOMEM);
    }

    pool->dbuf  =   calloc(nbuf, ctx->snap);
    if (pool->dbuf == NULL) {
        gwlb_err(ctx, "Cannot alloc %u bytes for packet data\n", (nbuf * ctx->snap));
        return (DAQ_ERROR_NOMEM);
    }

    desc    =   &pool->pool[0];
    pptr    =   pool->dbuf;

    for (idx = 0; idx < nbuf; idx++, desc++) {
        desc->data  =   pptr;
        pptr       +=   ctx->snap;

        /* Initialize headers in descriptor */
        init_daq_msg(ctx, desc);
        init_daq_hdr(ctx, desc);

        /* Place it in freelist */
        desc->next  =   pool->flist;
        pool->flist =   desc;
    }

    pool->info.mem_size     =   (nbuf * sizeof(pktdesc_t));
    pool->info.size         =   nbuf;
    pool->info.available    =   nbuf;

    return (DAQ_SUCCESS);
}

/*
 * gwlb_rmpool
 * Release resources acquired for packet pool
 */
static void gwlb_rmpool (context_t *ctx)
{
    pktpool_t                   *pool;

    pool    =   &ctx->pool;

    if (pool) {
        free(pool->dbuf);
        free(pool->pool);

        pool->dbuf  =   NULL;
        pool->pool  =   NULL;
    }

    pool->flist             =   NULL;
    pool->info.available    =   0;
    pool->info.mem_size     =   0;
}

/*
 * gwlb_send
 * Send packet out after swapping L2 & L3 addresses
 */
static int gwlb_send(context_t *ctx, const uint8_t *data, uint32_t dlen)
{
    uint8_t                     *ptr;

    /* Get a writable pointer to packet data */
    ptr     =   (uint8_t *) data;

    /* Swap L2 & L3 addresses */
    swap_l2_addr(ptr);
    swap_l3_addr(ptr);

    /* Send it on its merry way */
    if (nic_write(ctx->nic, ptr, dlen) < 0) {
        return (DAQ_ERROR);
    }

    return (DAQ_SUCCESS);
}

/*
 * gwlb_load
 * Load gwlb DAQ module
 */
static int gwlb_load (const DAQ_BaseAPI_t *base)
{
    if ((base->api_version != DAQ_BASE_API_VERSION) || (base->api_size != sizeof(DAQ_BaseAPI_t))) {
        return (DAQ_ERROR);
    }

    api     =   *base;

    return (DAQ_SUCCESS);
}

/*
 * gwlb_unload
 * Unload gwlb DAQ module
 */
static int gwlb_unload (void)
{
    memset(&api, 0, sizeof(DAQ_BaseAPI_t));

    return (DAQ_SUCCESS);
}

/*
 * gwlb_getvars
 * Return parameter table for this DAQ
 */
static int gwlb_getvars (const DAQ_VariableDesc_t **tbl)
{
    *tbl    =   NULL;
    return (0);
}

/*
 * gwlb_instantiate
 * Instantiate the module
 */
static int gwlb_instantiate (const DAQ_ModuleConfig_h cfg, DAQ_ModuleInstance_h inst, void **cptr)
{
    context_t                   *ctx;
    unsigned                    nbuf;
    int                         ret;

    ctx     =   calloc(1, sizeof(context_t));
    if (ctx == NULL) {
        return (DAQ_ERROR_NOMEM);
    }

    ctx->inst       =   inst;
    ctx->snap       =   api.config_get_snaplen(cfg);

    nbuf            =   api.config_get_msg_pool_size(cfg);
    nbuf            =   nbuf ? nbuf : MIN_POOL_SZ;
    ret             =   gwlb_mkpool(ctx, nbuf);
    if (ret != DAQ_SUCCESS) {
        gwlb_rmpool(ctx);
        free(ctx);
        return (ret);
    }

    ctx->mode       =   api.config_get_mode(cfg);
    ctx->input      =   strdup(api.config_get_input(cfg));
    if (ctx->input == NULL) {
        gwlb_err(ctx, "Need input");
        gwlb_rmpool(ctx);
        free(ctx);
        return (DAQ_ERROR_NOMEM);
    }

    ctx->wtime      =   api.config_get_timeout(cfg);
    if (ctx->wtime == 0) {
        ctx->wtime  =   -1;
    }

    ctx->nic        =   nic_open(ctx->input);
    if (ctx->nic == NULL) {
        gwlb_rmpool(ctx);
        free(ctx);
        return (DAQ_ERROR);
    }

    *cptr           =   ctx;
        
    return (DAQ_SUCCESS);
}

/*
 * gwlb_destroy
 * Destroy instance of the module
 */
static void gwlb_destroy (void *handle)
{
    context_t                   *ctx;

    ctx     =   handle;

    if (ctx == NULL) {
        return;
    }

    if (ctx->input) {
        free(ctx->input);
    }

    gwlb_rmpool(ctx);
}

/*
 * gwlb_start
 * Start the module
 */
static int gwlb_start (void *handle)
{
    return (DAQ_SUCCESS);
}

/*
 * gwlb_intr
 * Handle interrupt
 */
static int gwlb_intr (void *handle)
{
    context_t                   *ctx;

    ctx         =   handle;
    ctx->intr   =   true;

    return (DAQ_SUCCESS);
}

/*
 * gwlb_stop
 * Stop the module
 */
static int gwlb_stop (void *handle)
{
    context_t                   *ctx;

    ctx         =   handle;

    if (ctx->nic != NULL) {
        nic_close(ctx->nic);
    }

    return (DAQ_SUCCESS);
}

/*
 * gwlb_inject
 * Inject a packet
 */
static int gwlb_inject (void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t dlen)
{
    context_t                   *ctx;

    ctx         =   handle;
    ctx->stats.packets_injected++;

    /* No need to swap L2 & L3 addresses before putting the packet on wire */
    if (nic_write(ctx->nic, (uint8_t *)data, dlen) < 0) {
        return (DAQ_ERROR);
    }

    return (DAQ_SUCCESS);
}

/*
 * gwlb_inject_relative
 * Inject a packet relative to what?
 */
static int gwlb_inject_relative (void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t dlen, int reverse)
{
    context_t                   *ctx;

    ctx         =   handle;
    ctx->stats.packets_injected++;

    /* No need to swap L2 & L3 addresses before putting the packet on wire */
    if (nic_write(ctx->nic, (uint8_t *)data, dlen) < 0) {
        return (DAQ_ERROR);
    }

    return (DAQ_SUCCESS);
}

/*
 * gwlb_ioctl
 * IOCTL Handle for this module
 */
static int gwlb_ioctl (void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    printf("\033[31mIOCTL %d\033[0m\n", cmd);
    return (DAQ_SUCCESS);
}

/*
 * gwlb_stats
 * Get module stats
 */
static int gwlb_stats (void *handle, DAQ_Stats_t *stats)
{
    context_t                   *ctx;

    ctx     =   handle;

    memcpy(stats, &ctx->stats, sizeof(DAQ_Stats_t));

    return (DAQ_SUCCESS);
}

/*
 * gwlb_zstats
 * Reset module stats
 */
static void gwlb_zstats (void *handle)
{
    context_t                   *ctx;

    ctx     =   handle;

    memset(&ctx->stats, 0, sizeof(DAQ_Stats_t));
}

/*
 * gwlb_snaplen
 * Return snaplen of this module
 */
static int gwlb_snaplen (void *handle)
{
    context_t                   *ctx;

    ctx     =   handle;

    return (ctx->snap);
}

/*
 * gwlb_caps
 * Return capabilities of this module
 */
static uint32_t gwlb_caps (void *handle)
{
    uint32_t                    caps;

    caps    =   0;
    caps   |=  DAQ_CAPA_BLOCK;
    caps   |=  DAQ_CAPA_REPLACE;
    caps   |=  DAQ_CAPA_INJECT;
    caps   |=  DAQ_CAPA_DEVICE_INDEX;

    return (caps);
}

/*
 * gwlb_dlt
 * Return data link type of this module
 */
static int gwlb_dlt (void *handle)
{
    return (DLT_EN10MB);
}

/*
 * do_poll
 * Check if there are any packets available to read
 */
static DAQ_RecvStatus do_poll (context_t *ctx)
{
    struct pollfd               pfd;
    int                         wtime;
    int                         ptime;
    int                         ret;

    pfd.fd      =   ctx->nic->sock;
    pfd.revents =   0;
    pfd.events  =   POLLIN;

    wtime       =   ctx->wtime;

    while (wtime != 0) {
        if (ctx->intr == true) {
            ctx->intr   =   false;
            return (DAQ_RSTAT_INTERRUPTED);
        }

        ptime   =   MIN(wtime, 1000);
        wtime  -=   ptime;

        ret     =   poll(&pfd, 1, ptime);
        if ((ret < 0) && (ret != EINTR)) {
            gwlb_err(ctx, "poll: %m\n");
            return (DAQ_RSTAT_ERROR);
        }

        if (ret > 0) {
            if (pfd.revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)) {
                return (DAQ_RSTAT_ERROR);
            }

            return (DAQ_RSTAT_OK);
        }
    }

    return DAQ_RSTAT_TIMEOUT;
}

/*
 * gwlb_recv
 * Receive packets from device
 */
static unsigned gwlb_recv (void *handle, const unsigned max, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rst)
{
    context_t                   *ctx;
    pktdesc_t                   *desc;
    DAQ_Msg_t                   *daqmsg;
    DAQ_PktHdr_t                *pkthdr;
    DAQ_RecvStatus              rc;
    struct timeval              ts;
    unsigned                    idx;
    int                         nread;

    ctx     =   handle;
    *rst    =   DAQ_RSTAT_OK;

    rc      =   do_poll(ctx);
    if (rc != DAQ_RSTAT_OK) {
        *rst    =   rc;
        return (0);
    }

    for (idx = 0; idx < max; idx++) {
        if (ctx->intr == true) {
            ctx->intr   =   false;
            *rst        =   DAQ_RSTAT_INTERRUPTED;
            break;
        }

        desc    =   gwlb_getdesc(ctx);
        if (desc == NULL) {
            *rst    =   DAQ_RSTAT_NOBUF;
            break;
        }

        nread   =   nic_read(ctx->nic, desc->data, ctx->snap);
        if (nread == 0) {
            gwlb_putdesc(ctx, desc);
            *rst    =   DAQ_RSTAT_WOULD_BLOCK;
            break;
        } else  if (nread < 0) {
            gwlb_putdesc(ctx, desc);
            *rst    =   DAQ_RSTAT_EOF;
            break;
        }

        gettimeofday(&ts, NULL);

        desc->pktlen        =   nread;

        /* Fill in DAQ Message header */
        daqmsg              =   &desc->msg;
        daqmsg->data_len    =   nread;

        /* Fill in DAQ Packet header */
        pkthdr              =   &desc->hdr;
        pkthdr->pktlen      =   nread;
        pkthdr->ts.tv_sec   =   ts.tv_sec;
        pkthdr->ts.tv_usec  =   ts.tv_usec;

        msgs[ idx ] =   &desc->msg;
        ctx->stats.packets_received++;
    }

    return (idx);
}

/*
 * gwlb_finalize
 * Send a packet to device
 */
static int gwlb_finalize (void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    context_t                   *ctx;
    pktdesc_t                   *desc;
    int                         ret;

    ret     =   DAQ_SUCCESS;
    ctx     =   handle;
    desc    =   msg->priv;

    /* Bump verdicts counter */
    ctx->stats.verdicts[ verdict ]++;

    if ((verdict != DAQ_VERDICT_BLOCK) && (verdict != DAQ_VERDICT_BLACKLIST)) {
        ret =   gwlb_send(ctx, desc->data, desc->pktlen);
    }

    /* Put descriptor in free list */
    gwlb_putdesc(ctx, desc);

    return (ret);
}

/*
 * gwlb_poolinfo
 * Return modules pool info
 */
static int gwlb_poolinfo (void *handle, DAQ_MsgPoolInfo_t *info)
{
    context_t                   *ctx;

    ctx     =   handle;
    *info   =   ctx->pool.info;

    return (DAQ_SUCCESS);
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const  DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const  DAQ_ModuleAPI_t          gwlb_data    =
#endif
{
    /* .api_version = */        DAQ_MODULE_API_VERSION,
    /* .api_size = */           sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */     GWLB_VERSION,
    /* .name = */               "gwlb",
    /* .type = */               (DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE),
    /* .load = */               gwlb_load,
    /* .unload = */             gwlb_unload,
    /* .get_variable_descs = */ gwlb_getvars,
    /* .instantiate  = */       gwlb_instantiate,
    /* .destroy = */            gwlb_destroy,
    /* .set_filter = */         NULL,
    /* .start = */              gwlb_start,
    /* .inject = */             gwlb_inject,
    /* .inject_relative = */    gwlb_inject_relative,
    /* .interrupt = */          gwlb_intr,
    /* .stop = */               gwlb_stop,
    /* .ioctl = */              gwlb_ioctl,
    /* .get_stats = */          gwlb_stats,
    /* .reset_stats = */        gwlb_zstats,
    /* .get_snaplen = */        gwlb_snaplen,
    /* .get_capabilities = */   gwlb_caps,
    /* .get_datalink_type = */  gwlb_dlt,
    /* .config_load = */        NULL,
    /* .config_swap = */        NULL,
    /* .config_free = */        NULL,
    /* .msg_receive = */        gwlb_recv,
    /* .msg_finalize = */       gwlb_finalize,
    /* .get_msg_pool_info = */  gwlb_poolinfo,
};

