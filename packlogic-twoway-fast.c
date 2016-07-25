/*
** Copyright (C) 2005-2016 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
** See license information in ../../LICENSE.txt
** @OPENSOURCE_LICENSE_END@
*/

/*
**  Support file for probeconf.c
**
*/

#include <silk/silk.h>

#include <silk/rwflowpack.h>
#include <silk/rwrec.h>
#include <silk/silk_files.h>
#include <silk/sksite.h>
#include <silk/skvector.h>
#include <silk/utils.h>

#include "patricia.h"


/* TYPEDEFS AND MACROS */

/*
 *    Whether to split the web data separately from the other data;
 *    that is, whether to use the "inweb" and "outweb" flowtypes.
 *
 *    Web data is any flow seen on ports 80/tcp, 8080/tcp, 443/tcp.
 */
#ifndef SK_ENABLE_WEB_SPLIT
#  define SK_ENABLE_WEB_SPLIT   1
#endif

/*
 *    Whether to split ICMP data separately from the other data; that
 *    is, whether to use the "inicmp" and "outicmp" flowtypes.
 *
 *    ICMP data is any flow where proto == 1.
 */
#ifndef SK_ENABLE_ICMP_SPLIT
#  define SK_ENABLE_ICMP_SPLIT  0
#endif


/*
 *    Define integers to stand-in for each of the possible flowtypes
 *    that are defined in the silk.conf file.  These must match.
 */
#define RW_IN        0
#define RW_OUT       1
#define RW_IN_WEB    2
#define RW_OUT_WEB   3
#define RW_IN_NULL   4
#define RW_OUT_NULL  5
#define RW_INT2INT   6
#define RW_EXT2EXT   7
#define RW_IN_ICMP   8
#define RW_OUT_ICMP  9
#define RW_OTHER    10


/*
 *    These are the IDs of the networks that should be defined in the
 *    sensor.conf file.  We are in trouble if someone redefines these
 *    values.
 */
#define NUM_NETWORKS        3

#define NETWORK_NULL        ((skpc_network_id_t)0)
/* The SNMP interface on the probe to which non-routed traffic is
 * sent.  This is 0 on Cisco routers. */

#define NETWORK_EXTERNAL    ((skpc_network_id_t)1)
/* A bitmap where an ON bit represents an SNMP interface on the
 * probe that faces the external world.  Traffic entering the
 * router on this interface will be considered incoming. */

#define NETWORK_INTERNAL    ((skpc_network_id_t)2)
/* A bitmap where an ON bit represents an SNMP interface on the
 * probe that faces the internal world.  Traffic entering the
 * router on this interface will be considered outgoing. */


/* LOCAL VARIABLES */

/* the names that correspond to each network */
static const char *net_names[NUM_NETWORKS] = {
    "null",
    "external",
    "internal"
};

/*
 *    Define the file formats used to pack each flowtype.  If these do
 *    not line up with the type IDs defined in the config file, there
 *    will be problems.  Use the more compact formats for flows from
 *    NetFlow v5 based sources, and the expanded formats for flows
 *    from other sources.
 */
static struct filetypeFormats_st {
    sk_file_format_t    netflow_v5;
    sk_file_format_t    other;
} filetypeFormats[] = {
    /* in      */  {FT_RWSPLIT, FT_RWAUGMENTED},
    /* out     */  {FT_RWSPLIT, FT_RWAUGMENTED},
    /* inweb   */  {FT_RWWWW,   FT_RWAUGWEB},
    /* outweb  */  {FT_RWWWW,   FT_RWAUGWEB},
    /* innull  */  {FT_RWSPLIT, FT_RWAUGMENTED},
    /* outnull */  {FT_RWSPLIT, FT_RWAUGMENTED},
    /* int2int */  {FT_RWSPLIT, FT_RWAUGMENTED},
    /* ext2ext */  {FT_RWSPLIT, FT_RWAUGMENTED},
    /* inicmp  */  {FT_RWSPLIT, FT_RWAUGMENTED},
    /* outicmp */  {FT_RWSPLIT, FT_RWAUGMENTED},
    /* other   */  {FT_RWSPLIT, FT_RWAUGMENTED}
};


static const char plugin_source[] = __FILE__;
static const char *plugin_path = plugin_source;


/* LOCAL FUNCTION PROTOTYPES */

static int  packLogicSetup(void);
static void packLogicTeardown(void);
static int  packLogicVerifySensor(skpc_sensor_t *sensor);
static int
packLogicDetermineFlowtype(
    const skpc_probe_t *probe,
    const rwRec        *rwrec,
    sk_flowtype_id_t   *ftypes,
    sk_sensor_id_t     *sensorids);
static sk_file_format_t
packLogicDetermineFileFormat(
    const skpc_probe_t *probe,
    sk_flowtype_id_t    ftype);


/* FUNCTION DEFINITIONS */

/*
 *    Fill in 'packlogic' with pointers to the functions defined in
 *    this file.
 */
int
packLogicInitialize(
    packlogic_plugin_t *packlogic)
{
    assert(packlogic);

    if (packlogic->path) {
        plugin_path = packlogic->path;
    }

    packlogic->setup_fn =                &packLogicSetup;
    packlogic->teardown_fn =             &packLogicTeardown;
    packlogic->verify_sensor_fn =        &packLogicVerifySensor;
    packlogic->determine_flowtype_fn =   &packLogicDetermineFlowtype;
    packlogic->determine_fileformat_fn = &packLogicDetermineFileFormat;
    return 0;
}


/*
 *    Verify contents of silk.conf file matches the values we set here
 *    and set any globals we require.
 *
 *    Invoked from rwflowpack by packlogic->setup_fn
 */
static int
packLogicSetup(
    void)
{
    const size_t count = (sizeof(filetypeFormats)/sizeof(filetypeFormats[0]));
    uint32_t i;

#define FT_ASSERT(flowtype_id, flowtype_name)                           \
    sksiteFlowtypeAssert(plugin_path, (flowtype_id), "all", (flowtype_name))

    /* Make sure flowtype definitions match config file */
    FT_ASSERT(RW_IN,       "in");
    FT_ASSERT(RW_OUT,      "out");
    FT_ASSERT(RW_IN_WEB,   "inweb");
    FT_ASSERT(RW_OUT_WEB,  "outweb");
    FT_ASSERT(RW_IN_NULL,  "innull");
    FT_ASSERT(RW_OUT_NULL, "outnull");
    FT_ASSERT(RW_INT2INT,  "int2int");
    FT_ASSERT(RW_EXT2EXT,  "ext2ext");
    FT_ASSERT(RW_IN_ICMP,  "inicmp");
    FT_ASSERT(RW_OUT_ICMP, "outicmp");
    FT_ASSERT(RW_OTHER,    "other");

    /* Confirm that number of flowtypes is not greater than the size
     * of the filetypeFormats[] array; abort if it is.  Complain if
     * the array is too large, but continue processing.  */
    if (count <= sksiteFlowtypeGetMaxID()) {
        skAppPrintErr(("File formats not specified for some flowtypes.\n"
                       "\tModify filetypeFormats[] in %s,\n"
                       "\trecompile and try running again."),
                      plugin_path);
        skAbort();
    } else if (count != (1u + sksiteFlowtypeGetMaxID())) {
        skAppPrintErr(("Warning: Number of flowtypes does not equal number\n"
                       "\tof file formats in filetypeFormats[] in %s"),
                      plugin_path);
    }

    /* Define all of our networks */
    for (i = 0; i < NUM_NETWORKS; ++i) {
        if (skpcNetworkAdd(i, net_names[i])) {
            skAppPrintErr("Unable to add network %" PRIu32 "->%s",
                          i, net_names[i]);
            return -1;
        }
    }

    return 0;
}


/*
 *    Clean up any memory we allocated.
 *
 *    Invoked from rwflowpack by packlogic->teardown_fn
 */
static void
packLogicTeardown(
    void)
{
    return;
}


/* Convert a Silk netblock to a Patricia prefix */
prefix_t* prefixFromBlock(skIPWildcard_t *block)
{
uint8_t in6_min[16];
skIPWildcardIterator_t iter;
skipaddr_t ipaddr;
uint32_t cidr_prefix;

skIPWildcardIteratorBind(&iter,block);

int i=0;

/* Only support a single wildcard */
while (skIPWildcardIteratorNextCidr(&iter, &ipaddr, &cidr_prefix) == SK_ITERATOR_OK)
{
	skipaddrGetAsV6(&ipaddr,in6_min);
	i++;
}

if (i != 1) {
        fprintf(stderr,"Iterator returned more than 1\n");
        abort();
}

uint8_t is_v6;

is_v6 = skipaddrIsV6(&ipaddr);

if (!is_v6) {
        cidr_prefix+=96;
}

prefix_t* prefix;

prefix=calloc(1,sizeof(prefix_t));

prefix->family=AF_INET6;
prefix->bitlen=cidr_prefix;
memcpy(prefix->add.sin6.s6_addr,in6_min,16);
prefix->ref_count++;

return prefix;

}


/*
 *    Verify sensor by its class.  Verify that the sensor supports the
 *    type(s) of its probe(s).  Verify that enough information is
 *    present on the sensor to categorize a flow record.
 *
 *    Invoked from rwflowpack by packlogic->verify_sensor_fn
 */
static int
packLogicVerifySensor(
    skpc_sensor_t      *sensor)
{
    unsigned int nd_type_count[SKPC_NUM_NETDECIDER_TYPES];
    unsigned int block_count;
    unsigned int set_count;
    unsigned int if_count;
    unsigned int i;
    skpc_probe_t *probe;
    sk_vector_t *probe_vec;
    uint32_t probe_count;
    uint32_t c;
    prefix_t *prefix;
    patricia_tree_t *tree;

    /* There is a single class, so no per-class verification is
     * necessary.  Make certain each sensor has snmp interface values,
     * ipblocks, or IPsets to categorize each flow. */

    /* get the probes for the sensor */
    probe_vec = skVectorNew(sizeof(skpc_probe_t*));
    if (probe_vec == NULL) {
        return -1;
    }
    probe_count = skpcSensorGetProbes(sensor, probe_vec);

    /* verify each probe */
    for (c = 0; c < probe_count; ++c) {
        skVectorGetValue(&probe, probe_vec, c);

        /* make certain the probe's type is valid */
        switch (probe->probe_type) {
          case PROBE_ENUM_NETFLOW_V5:
          case PROBE_ENUM_NETFLOW_V9:
          case PROBE_ENUM_IPFIX:
          case PROBE_ENUM_SFLOW:
          case PROBE_ENUM_SILK:
            /* supported probe types */
            break;

          default:
            assert(skpcProbetypeEnumtoName(probe->probe_type));
            skAppPrintErr(("Cannot verify sensor '%s':\n"
                           "\tThe probe type '%s' is not supported in the"
                           " packing-logic\n\tfile '%s'"),
                          sensor->sensor_name,
                          skpcProbetypeEnumtoName(probe->probe_type),
                          plugin_path);
            skVectorDestroy(probe_vec);
            return -1;
        }
	if (probe->file_source == NULL) {
	  // Initialize if not already for this probe 
          probe->file_source=(char*) New_Patricia(128);
	}
    }
    skVectorDestroy(probe_vec);

    /* Populate patricia trie with *internal* ipblocks */
    if (sensor->decider[NETWORK_INTERNAL].nd_type == SKPC_IPBLOCK ) {
	patricia_node_t *node;
        for (i=0; i < sensor->decider[NETWORK_INTERNAL].nd_group->g_itemcount;i++) {
		prefix=prefixFromBlock(sensor->decider[NETWORK_INTERNAL].nd_group->g_value.ipblock[i]);
	
		/* Add this prefix to a tree on every probe which it is associated with */
		int j;
                for (j=0; j < sensor->probe_count; j++) {
                        tree=(patricia_tree_t*)(sensor->probe_list[j]->file_source);
                        node=patricia_lookup(tree,prefix);
                        node->user1=(void*)sensor; //->sensor_id;
                }
                Deref_Prefix(prefix);
	}
    }


    /* If the source and destination networks are set, we're
     * good to go.  Ideally, there should be a way to say that all
     * traffic is from a particular network, but that we want to
     * categorize it by where it goes.  For example, consider a router
     * where we only monitor incoming traffic, but we still want to
     * distinguish ACLed traffic from routed. */
    if ((sensor->fixed_network[0] != SKPC_NETWORK_ID_INVALID)
        && (sensor->fixed_network[1] != SKPC_NETWORK_ID_INVALID))
    {
        return 0;
    }

    /*
     * Verify that we have enough information to determine the
     * flowtype for every flow.  These are the rules:
     *
     * 1. One of NET-interface, NET-ipblock, or NET-ipset must be
     * specified, where NET is either "internal" or "external".
     *
     * 2. A null-interface is always allowed.  Otherwise, each sensor
     * must only use one of ipblocks, ipsets, and interfaces.
     *
     * 3. Only one network may claim the remainder.
     *
     * 4. Using 'remainder' for an ipblock or an ipset requires that
     * another NET has set an IPblock or an IPset.  (Not required for
     * interfaces.)
     *
     * 5. If only one of internal-* or external-* is set, set the
     * other to the remaining values, unless the 'remainder' is
     * already claiming them.
     */

    /* for this sensor, count how many of each decider type (e.g.,
     * SKPC_IBLOCK (NET-ipblock)) have been specified */
    memset(nd_type_count, 0, sizeof(nd_type_count));
    for (i = 0; i < NUM_NETWORKS; ++i) {
        assert(sensor->decider[i].nd_type < SKPC_NUM_NETDECIDER_TYPES);
        ++nd_type_count[sensor->decider[i].nd_type];
    }

    /* get number of deciders for ipblocks and for interfaces */
    if_count = (nd_type_count[SKPC_INTERFACE]
                + nd_type_count[SKPC_REMAIN_INTERFACE]);
    block_count = (nd_type_count[SKPC_IPBLOCK]
                   + nd_type_count[SKPC_REMAIN_IPBLOCK]);
    set_count = (nd_type_count[SKPC_IPSET]
                 + nd_type_count[SKPC_REMAIN_IPSET]);

    if (nd_type_count[SKPC_NEG_IPBLOCK]) {
        /* this should never happen, since there is no way to set this
         * from the sensor.conf file  */
        skAppPrintErr("Negated IPblock logic not implemented");
        exit(EXIT_FAILURE);
    }
    if (nd_type_count[SKPC_NEG_IPSET]) {
        /* this should never happen, since there is no way to set this
         * from the sensor.conf file  */
        skAppPrintErr("Negated IPset logic not implemented");
        exit(EXIT_FAILURE);
    }

    /* make certain ipblocks, ipsets, or interfaces are specified, and
     * make certain something in addition to null-* is specified */
    if ((block_count + if_count + set_count == 0)
        || ((block_count + if_count + set_count == 1)
            && (sensor->decider[NETWORK_NULL].nd_type != SKPC_UNSET)))
    {
        skAppPrintErr(("Cannot verify sensor %s:\n"
                       "\tMust specify source-network and"
                       " destination-network, or at least one\n"
                       "\tof %s- and %s-interface, %s- and %s-ipblock,"
                       " or %s- and %s-ipset"),
                      sensor->sensor_name,
                      net_names[NETWORK_EXTERNAL],net_names[NETWORK_INTERNAL],
                      net_names[NETWORK_EXTERNAL],net_names[NETWORK_INTERNAL],
                      net_names[NETWORK_EXTERNAL],net_names[NETWORK_INTERNAL]);
        return -1;
    }

    /* only one 'remainder' is allowed */
    if ((nd_type_count[SKPC_REMAIN_IPBLOCK]
         + nd_type_count[SKPC_REMAIN_INTERFACE]
         + nd_type_count[SKPC_REMAIN_IPSET])
        > 1)
    {
        skAppPrintErr(("Cannot verify sensor '%s':\n"
                       "\tOnly one network value may use 'remainder'"),
                      sensor->sensor_name);
        return -1;
    }

    /* handle case where NET-ipblocks are set */
    if (block_count) {
        if (block_count == NUM_NETWORKS) {
            /* all networks were specified. nothing else to check */
            assert(if_count == 0);
            assert(set_count == 0);
            return 0;
        }
        /* block_count is either 1 or 2 */
        assert(block_count <= 2);

        if (set_count) {
            skAppPrintErr(("Cannot verify sensor '%s':\n"
                           "\tCannot mix <NET>-ipblock and <NET>-ipset"),
                          sensor->sensor_name);
            return -1;
        }

        /* only valid mix of NET-ipblock and NET-interface is for the
         * interfaces to be on the NULL network */
        if (if_count) {
            switch (sensor->decider[NETWORK_NULL].nd_type) {
              case SKPC_INTERFACE:
              case SKPC_REMAIN_INTERFACE:
                --if_count;
                break;

              default:
                break;
            }
            if (if_count) {
                skAppPrintErr(("Cannot verify sensor '%s':\n"
                               "\tCannot mix <NET>-interface"
                               " and <NET>-ipblock"),
                              sensor->sensor_name);
                return -1;
            }
        }

        /* if an ipblock has claimed the 'remainder', verify we have
         * IPs specified elsewhere and return */
        if (nd_type_count[SKPC_REMAIN_IPBLOCK] == 1) {
            /* need at least one IP address to be specified for
             * 'remainder' to work */
            if (block_count == 1) {
                skAppPrintErr(("Cannot verify sensor '%s':\n"
                               "\tCannot set ipblocks to remainder when"
                               " no other networks hold IP blocks"),
                              sensor->sensor_name);
                return -1;
            }
            return 0;
        }

        /* if either EXTERNAL or INTERNAL is unset, set to remainder */
        if (sensor->decider[NETWORK_EXTERNAL].nd_type == SKPC_UNSET) {
            assert(sensor->decider[NETWORK_INTERNAL].nd_type == SKPC_IPBLOCK);
            sensor->decider[NETWORK_EXTERNAL].nd_type = SKPC_REMAIN_IPBLOCK;
        }
        if (sensor->decider[NETWORK_INTERNAL].nd_type == SKPC_UNSET) {
            assert(sensor->decider[NETWORK_EXTERNAL].nd_type == SKPC_IPBLOCK);
            sensor->decider[NETWORK_INTERNAL].nd_type = SKPC_REMAIN_IPBLOCK;
        }

        return 0;
    }

    /* handle case where NET-ipsets are set */
    if (set_count) {
        if (set_count == NUM_NETWORKS) {
            /* all networks were specified. nothing else to check */
            assert(if_count == 0);
            assert(block_count == 0);
            return 0;
        }
        /* set_count is either 1 or 2 */
        assert(set_count <= 2);

        if (block_count) {
            skAppPrintErr(("Cannot verify sensor '%s':\n"
                           "\tCannot mix <NET>-ipset and <NET>-ipblock"),
                          sensor->sensor_name);
            return -1;
        }

        /* only valid mix of NET-ipset and NET-interface is for the
         * interfaces to be on the NULL network */
        if (if_count) {
            switch (sensor->decider[NETWORK_NULL].nd_type) {
              case SKPC_INTERFACE:
              case SKPC_REMAIN_INTERFACE:
                --if_count;
                break;

              default:
                break;
            }
            if (if_count) {
                skAppPrintErr(("Cannot verify sensor '%s':\n"
                               "\tCannot mix <NET>-interface"
                               " and <NET>-ipset"),
                              sensor->sensor_name);
                return -1;
            }
        }

        /* if an ipset has claimed the 'remainder', verify we have
         * IPs specified elsewhere and return */
        if (nd_type_count[SKPC_REMAIN_IPSET] == 1) {
            /* need at least one IP address to be specified for
             * 'remainder' to work */
            if (set_count == 1) {
                skAppPrintErr(("Cannot verify sensor '%s':\n"
                               "\tCannot set ipsets to remainder when"
                               " no other networks hold IP sets"),
                              sensor->sensor_name);
                return -1;
            }
            return 0;
        }

        /* if either EXTERNAL or INTERNAL is unset, set to remainder */
        if (sensor->decider[NETWORK_EXTERNAL].nd_type == SKPC_UNSET) {
            assert(sensor->decider[NETWORK_INTERNAL].nd_type == SKPC_IPSET);
            sensor->decider[NETWORK_EXTERNAL].nd_type = SKPC_REMAIN_IPSET;
        }
        if (sensor->decider[NETWORK_INTERNAL].nd_type == SKPC_UNSET) {
            assert(sensor->decider[NETWORK_EXTERNAL].nd_type == SKPC_IPSET);
            sensor->decider[NETWORK_INTERNAL].nd_type = SKPC_REMAIN_IPSET;
        }

        return 0;
    }

    /* handle case where NET-interfaces are set */
    if (0 == if_count || block_count > 0 || set_count > 0) {
        skAppPrintErr("Programmer error");
        skAbort();
    }

    if (if_count == NUM_NETWORKS) {
        /* all networks were specified. nothing else to check */
        return 0;
    }
    /* if_count is either 1 or 2. */
    assert(if_count <= 2);

    /* if someone has claimed the 'remainder', there is nothing else
     * to do. */
    if (nd_type_count[SKPC_REMAIN_INTERFACE] == 1) {
        /* unlike the ipblock case, 'remainder' by itself is legal */
        return 0;
    }

    /* if either EXTERNAL or INTERNAL is unset, set to remainder */
    if (sensor->decider[NETWORK_EXTERNAL].nd_type == SKPC_UNSET) {
        assert(sensor->decider[NETWORK_INTERNAL].nd_type==SKPC_INTERFACE);
        sensor->decider[NETWORK_EXTERNAL].nd_type = SKPC_REMAIN_INTERFACE;
    }
    if (sensor->decider[NETWORK_INTERNAL].nd_type == SKPC_UNSET) {
        assert(sensor->decider[NETWORK_EXTERNAL].nd_type==SKPC_INTERFACE);
        sensor->decider[NETWORK_INTERNAL].nd_type = SKPC_REMAIN_INTERFACE;
    }

    return 0;
}

skpc_sensor_t* searchTree(patricia_tree_t *tree, skipaddr_t *ipaddr) {
    /* Searches the tree for ip and returns the sensor id */
    prefix_t prefix;
    patricia_node_t *node;

    memset(&prefix,0,sizeof(prefix_t));

    uint8_t in6_min[16];

    skipaddrGetAsV6(ipaddr,in6_min);

    prefix.family=AF_INET6;
    prefix.bitlen=128;
    memcpy(prefix.add.sin6.s6_addr,in6_min,16);
    prefix.ref_count++;
    node = patricia_search_best (tree, &prefix);

    if (node) {
    // We have a match so short circuit remaining logic
        return (skpc_sensor_t*)node->user1;
    } else {
        return NULL;
    }

}



/*
 *  count = packLogicDetermineFlowtype(probe, &rwrec, ftypes[], sensorids[]);
 *
 *    Fill the 'ftypes' and 'sensorids' arrays with the list of
 *    flow_types and sensors to which the 'rwrec' probe, collected
 *    from the 'probe' sensor, should be packed.  Return the number of
 *    elements added to each array or -1 on error.
 *
 *    Invoked from rwflowpack by packlogic->determine_flowtype_fn
 */
static int
packLogicDetermineFlowtype(
    const skpc_probe_t *probe,
    const rwRec        *rwrec,
    sk_flowtype_id_t   *ftypes,
    sk_sensor_id_t     *sensorids)
{
    skpc_sensor_t *sensor;
    patricia_tree_t *tree;
    skipaddr_t ipaddr;

    assert(ftypes);
    assert(sensorids);

    tree=(patricia_tree_t*)probe->file_source;

    /* Check for sip match */
    rwrec_MemGetSIP(rwrec,&ipaddr);

    sensor=searchTree(tree,&ipaddr); 
    if (sensor) {
        sensorids[0]=sensor->sensor_id;
        if (sensor->decider[NETWORK_NULL].nd_type == SKPC_REMAIN_IPBLOCK) {
                ftypes[0]=RW_OUT_NULL;
        } else {
                if rwRecIsWeb(rwrec)
                ftypes[0]=RW_OUT_WEB;
                else
                ftypes[0]=RW_OUT;
        }
        return 1;
    } else {
	        /* Check for dip match */
        rwrec_MemGetDIP(rwrec,&ipaddr);
        sensor=searchTree(tree,&ipaddr);
        if (sensor) {
                sensorids[0]=sensor->sensor_id;
                if (sensor->decider[NETWORK_NULL].nd_type == SKPC_REMAIN_IPBLOCK) {
                ftypes[0]=RW_IN_NULL;
                } else {
                if rwRecIsWeb(rwrec)
                        ftypes[0]=RW_IN_WEB;
                else
                        ftypes[0]=RW_IN;
                }
                return 1;
        }
    }

    /* Else we haven't got an entry for this flow (eg a flow between two IPs which we have not configured */
    sensorids[0]=1;  /* 1 == OrgNone */
    ftypes[0]=RW_EXT2EXT;
    return 1;

}




/*
 *    Determine the file output format to use.
 *
 *    Invoked from rwflowpack by packlogic->determine_fileformat_fn
 */
#if  SK_ENABLE_IPV6

static sk_file_format_t
packLogicDetermineFileFormat(
    const skpc_probe_t  UNUSED(*probe),
    sk_flowtype_id_t     UNUSED(ftype))
{
    return FT_RWIPV6;
}

#else

static sk_file_format_t
packLogicDetermineFileFormat(
    const skpc_probe_t *probe,
    sk_flowtype_id_t    ftype)
{
    assert(ftype < (sizeof(filetypeFormats)/sizeof(filetypeFormats[0])));

    if (skpcProbeGetQuirks(probe) & SKPC_QUIRK_ZERO_PACKETS) {
        /* Use a format that does not use bytes/packet ratio */
        return FT_RWGENERIC;
    }

    switch (probe->probe_type) {
      case PROBE_ENUM_NETFLOW_V5:
        return filetypeFormats[ftype].netflow_v5;

      default:
        return filetypeFormats[ftype].other;
    }
}

#endif  /* #else of #if SK_ENABLE_IPV6 */

