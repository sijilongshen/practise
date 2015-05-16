/* capture_opts.h
 * Capture options (all parameters needed to do the actual capture)
 *
 * $Id: capture_opts.h 39498 2011-10-20 19:44:40Z tuexen $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


/** @file
 *
 *  Capture options (all parameters needed to do the actual capture)
 *
 */

#ifndef __CAPTURE_OPTS_H__
#define __CAPTURE_OPTS_H__

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>	    /* for gid_t */
#endif

#include "capture_ifinfo.h"

/* Current state of capture engine. XXX - differentiate states */
typedef enum {
    CAPTURE_STOPPED,        /**< stopped */
    CAPTURE_PREPARING,      /**< preparing, but still no response from capture child */
    CAPTURE_RUNNING         /**< capture child signalled ok, capture is running now */
} capture_state;

#ifdef HAVE_PCAP_REMOTE
/* Type of capture source */
typedef enum {
    CAPTURE_IFLOCAL,        /**< Local network interface */
    CAPTURE_IFREMOTE        /**< Remote network interface */
} capture_source;

/* Type of RPCAPD Authentication */
typedef enum {
    CAPTURE_AUTH_NULL,      /**< No authentication */
    CAPTURE_AUTH_PWD        /**< User/password authentication */
} capture_auth;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
/**
 * Method of packet sampling (dropping some captured packets),
 * may require additional integer parameter, marked here as N
 */
typedef enum {
    CAPTURE_SAMP_NONE,      /**< No sampling - capture all packets */
    CAPTURE_SAMP_BY_COUNT,  /**< Counter-based sampling -
                                 capture 1 packet from every N */
    CAPTURE_SAMP_BY_TIMER   /**< Timer-based sampling -
                                 capture no more than 1 packet
                                 in N milliseconds */
} capture_sampling;
#endif

#pragma pack(1)
typedef struct interface_options_tag {
    gchar *name;/*有*/
    gchar *descr;/*有*/
    gchar *cfilter;/*有*/
    gboolean has_snaplen;/*有*/
    int snaplen;/*有*/
    int linktype;/*有*/
    gboolean promisc_mode;/*有*/
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    int buffer_size;
#endif
    gboolean monitor_mode;/*有*/
#ifdef HAVE_PCAP_REMOTE
    capture_source src_type;
    gchar *remote_host;
    gchar *remote_port;
    capture_auth auth_type;
    gchar *auth_username;
    gchar *auth_password;
    gboolean datatx_udp;
    gboolean nocap_rpcap;
    gboolean nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    capture_sampling sampling_method;
    int sampling_param;
#endif
} interface_options;

/** Capture options coming from user interface */
typedef struct capture_options_tag {
    /* general */
    void     *cf;                   /**< handle to cfile (note: untyped handle) */
    GArray   *ifaces;               /**< array of interfaces.
                                         Currently only used by dumpcap. */
    interface_options default_options;

    gboolean group_read_access;     /**< TRUE is group read permission needs to be set */
    gboolean use_pcapng;            /**< TRUE if file format is pcapng */

    /* GUI related */
    gboolean real_time_mode;        /**< Update list of packets in real time */

    gboolean quit_after_cap;        /**< Makes a "capture only mode". Implies -k */
    gboolean restart;               /**< restart after closing is done */

    /* autostop conditions */
    gboolean has_autostop_packets;  /**< TRUE if maximum packet count is specified */
    int autostop_packets;           /**< Maximum packet count */

} capture_options;
#pragma pack()

/* initialize the capture_options with some reasonable values */
extern void
capture_opts_init(capture_options *capture_opts, void *cf);

/* set a command line option value */
extern int
capture_opts_add_opt(capture_options *capture_opts, int opt, const char *optarg, gboolean *start_capture);

/* log content of capture_opts */
extern void
capture_opts_log(const char *log_domain, GLogLevelFlags log_level, capture_options *capture_opts);

/* print interface capabilities, including link layer types */
extern void
capture_opts_print_if_capabilities(if_capabilities_t *caps, char *name,
                                   gboolean monitor_mode);

/* print list of interfaces */
extern void
capture_opts_print_interfaces(GList *if_list);

/* trim the snaplen entry */
extern void
capture_opts_trim_snaplen(capture_options *capture_opts, int snaplen_min);


/* trim the interface entry */
extern gboolean
capture_opts_trim_iface(capture_options *capture_opts, const char *capture_device);

#endif /* capture_opts.h */
