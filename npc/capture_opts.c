/* capture_opts.c
 * Routines for capture options setting
 *
 * $Id: capture_opts.c 39498 2011-10-20 19:44:40Z tuexen $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

//#ifdef HAVE_LIBPCAP

#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <stdlib.h>

#include <glib.h>

//#include <epan/packet.h>

#include "capture_opts.h"
//#include "ringbuffer.h"
//#include "clopts_common.h"
//#include "console_io.h"
//#include "cmdarg_err.h"

#include "capture_ifinfo.h"
#include "capture-pcap-util.h"
//#include <wsutil/file_util.h>

//#define	WTAP_MAX_PACKET_SIZE			65535
#define	WTAP_MAX_PACKET_SIZE			8192
#define RINGBUFFER_MIN_NUM_FILES		0
#define RINGBUFFER_MAX_NUM_FILES		100000
#define RINGBUFFER_WARN_NUM_FILES		65535

//static gboolean capture_opts_output_to_pipe(const char *save_file, gboolean *is_pipe);
extern GList *capture_interface_list(int *err, char **err_str);

int
get_natural_int(const char *string, const char *name)
{
	long number;
	char *p;

	number = strtol(string, &p, 10);
	if (p == string || *p != '\0') {
		fprintf(stderr,"The specified %s \"%s\" isn't a decimal number", name, string);
		exit(1);
	}
	if (number < 0) {
		fprintf(stderr,"The specified %s \"%s\" is a negative number", name, string);
		exit(1);
	}
	if (number > INT_MAX) {
		fprintf(stderr,"The specified %s \"%s\" is too large (greater than %d)",
			name, string, INT_MAX);
		exit(1);
	}
	return number;
}


int
get_positive_int(const char *string, const char *name)
{
	long number;

	number = get_natural_int(string, name);

	if (number == 0) {
		fprintf(stderr,"The specified %s is zero", name);
		exit(1);
	}

	return number;
}



void
capture_opts_init(capture_options *capture_opts, void *cf)
{
  capture_opts->cf                              = cf;
  capture_opts->ifaces                          = g_array_new(FALSE, FALSE, sizeof(interface_options));
  capture_opts->default_options.name            = NULL;
  capture_opts->default_options.descr           = NULL;
  capture_opts->default_options.cfilter         = NULL;
  capture_opts->default_options.has_snaplen     = FALSE;
  capture_opts->default_options.snaplen         = WTAP_MAX_PACKET_SIZE;
  capture_opts->default_options.linktype        = -1;
  capture_opts->default_options.promisc_mode    = TRUE;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  capture_opts->default_options.buffer_size     = 1;                /* 1 MB */
#endif
  capture_opts->default_options.monitor_mode    = FALSE;
#ifdef HAVE_PCAP_REMOTE
  capture_opts->default_options.src_type        = CAPTURE_IFLOCAL;
  capture_opts->default_options.remote_host     = NULL;
  capture_opts->default_options.remote_port     = NULL;
  capture_opts->default_options.auth_type       = CAPTURE_AUTH_NULL;
  capture_opts->default_options.auth_username   = NULL;
  capture_opts->default_options.auth_password   = NULL;
  capture_opts->default_options.datatx_udp      = FALSE;
  capture_opts->default_options.nocap_rpcap     = TRUE;
  capture_opts->default_options.nocap_local     = FALSE;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
  capture_opts->default_options.sampling_method = CAPTURE_SAMP_NONE;
  capture_opts->default_options.sampling_param  = 0;
#endif
  capture_opts->group_read_access               = FALSE;
#ifdef PCAP_NG_DEFAULT
  capture_opts->use_pcapng                      = TRUE;             /* Save as pcap-ng by default */
#else
  capture_opts->use_pcapng                      = FALSE;            /* Save as pcap by default */
#endif
  capture_opts->real_time_mode                  = TRUE;
  capture_opts->quit_after_cap                  = getenv("WIRESHARK_QUIT_AFTER_CAPTURE") ? TRUE : FALSE;
  capture_opts->restart                         = FALSE;

  capture_opts->has_autostop_packets            = FALSE;
  capture_opts->autostop_packets                = 0;



#ifdef _WIN32
  capture_opts->signal_pipe_write_fd            = -1;
#endif

#ifndef _WIN32
  //capture_opts->owner                           = getuid();
  //capture_opts->group                           = getgid();
#endif
}


#ifdef HAVE_PCAP_SETSAMPLING
/*
 * Given a string of the form "<sampling type>:<value>", as might appear
 * as an argument to a "-m" option, parse it and set the arguments in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
get_sampling_arguments(capture_options *capture_opts, const char *arg)
{
    gchar *p = NULL, *colonp;

    colonp = strchr(arg, ':');
    if (colonp == NULL)
        return FALSE;

    p = colonp;
    *p++ = '\0';

    while (isspace((guchar)*p))
        p++;
    if (*p == '\0') {
        *colonp = ':';
        return FALSE;
    }

    if (strcmp(arg, "count") == 0) {
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.sampling_method = CAPTURE_SAMP_BY_COUNT;
            interface_opts.sampling_param = get_positive_int(p, "sampling count");
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.sampling_method = CAPTURE_SAMP_BY_COUNT;
            capture_opts->default_options.sampling_param = get_positive_int(p, "sampling count");
        }
    } else if (strcmp(arg, "timer") == 0) {
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.sampling_method = CAPTURE_SAMP_BY_TIMER;
            interface_opts.sampling_param = get_positive_int(p, "sampling timer");
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.sampling_method = CAPTURE_SAMP_BY_TIMER;
            capture_opts->default_options.sampling_param = get_positive_int(p, "sampling timer");
        }
    }
    *colonp = ':';
    return TRUE;
}
#endif

#ifdef HAVE_PCAP_REMOTE
/*
 * Given a string of the form "<username>:<password>", as might appear
 * as an argument to a "-A" option, parse it and set the arguments in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
get_auth_arguments(capture_options *capture_opts, const char *arg)
{
    gchar *p = NULL, *colonp;

    colonp = strchr(arg, ':');
    if (colonp == NULL)
        return FALSE;

    p = colonp;
    *p++ = '\0';

    while (isspace((guchar)*p))
        p++;

    if (capture_opts->ifaces->len > 0) {
        interface_options interface_opts;

        interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
        interface_opts.auth_type = CAPTURE_AUTH_PWD;
        interface_opts.auth_username = g_strdup(arg);
        interface_opts.auth_password = g_strdup(p);
        g_array_append_val(capture_opts->ifaces, interface_opts);
    } else {
        capture_opts->default_options.auth_type = CAPTURE_AUTH_PWD;
        capture_opts->default_options.auth_username = g_strdup(arg);
        capture_opts->default_options.auth_password = g_strdup(p);
    }
    *colonp = ':';
    return TRUE;
}
#endif

static int
capture_opts_add_iface_opt(capture_options *capture_opts, const char *optarg_str_p)
{
    long        adapter_index;
    char        *p;
    GList       *if_list;
    if_info_t   *if_info;
    int         err;
    gchar       *err_str;
    interface_options interface_opts;


    /*
     * If the argument is a number, treat it as an index into the list
     * of adapters, as printed by "tshark -D".
     *
     * This should be OK on UNIX systems, as interfaces shouldn't have
     * names that begin with digits.  It can be useful on Windows, where
     * more than one interface can have the same name.
     */
    adapter_index = strtol(optarg_str_p, &p, 10);
    if (p != NULL && *p == '\0') {
        if (adapter_index < 0) {
            fprintf(stderr,"The specified adapter index is a negative number");
            return 1;
        }
        if (adapter_index > INT_MAX) {
            fprintf(stderr,"The specified adapter index is too large (greater than %d)",
                       INT_MAX);
            return 1;
        }
        if (adapter_index == 0) {
            fprintf(stderr,"There is no interface with that adapter index");
            return 1;
        }
        if_list = capture_interface_list(&err, &err_str);
        if (if_list == NULL) {
            switch (err) {

            case CANT_GET_INTERFACE_LIST:
                fprintf(stderr,"%s", err_str);
                g_free(err_str);
                break;

            case NO_INTERFACES_FOUND:
                fprintf(stderr,"There are no interfaces on which a capture can be done");
                break;
            }
            return 2;
        }
        if_info = (if_info_t *)g_list_nth_data(if_list, adapter_index - 1);
        if (if_info == NULL) {
            fprintf(stderr,"There is no interface with that adapter index");
            return 1;
        }
        interface_opts.name = g_strdup(if_info->name);
        /*  We don't set iface_descr here because doing so requires
         *  capture_ui_utils.c which requires epan/prefs.c which is
         *  probably a bit too much dependency for here...
         */
        free_interface_list(if_list);
    } else {
        interface_opts.name = g_strdup(optarg_str_p);
    }
    interface_opts.descr = g_strdup(capture_opts->default_options.descr);
    interface_opts.cfilter = g_strdup(capture_opts->default_options.cfilter);
    interface_opts.snaplen = capture_opts->default_options.snaplen;
    interface_opts.has_snaplen = capture_opts->default_options.has_snaplen;
    interface_opts.linktype = capture_opts->default_options.linktype;
    interface_opts.promisc_mode = capture_opts->default_options.promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    interface_opts.buffer_size = capture_opts->default_options.buffer_size;
#endif
    interface_opts.monitor_mode = capture_opts->default_options.monitor_mode;
#ifdef HAVE_PCAP_REMOTE
    interface_opts.src_type = capture_opts->default_options.src_type;
    interface_opts.remote_host = g_strdup(capture_opts->default_options.remote_host);
    interface_opts.remote_port = g_strdup(capture_opts->default_options.remote_port);
    interface_opts.auth_type = capture_opts->default_options.auth_type;
    interface_opts.auth_username = g_strdup(capture_opts->default_options.auth_username);
    interface_opts.auth_password = g_strdup(capture_opts->default_options.auth_password);
    interface_opts.datatx_udp = capture_opts->default_options.datatx_udp;
    interface_opts.nocap_rpcap = capture_opts->default_options.nocap_rpcap;
    interface_opts.nocap_local = capture_opts->default_options.nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    interface_opts.sampling_method = capture_opts->default_options.sampling_method;
    interface_opts.sampling_param  = capture_opts->default_options.sampling_param;
#endif

    g_array_append_val(capture_opts->ifaces, interface_opts);

    return 0;
}

int
capture_opts_add_opt(capture_options *capture_opts, int opt, const char *optarg_str_p, gboolean *start_capture)
{
    int status, snaplen;

    switch(opt) {
    case 'a':        /* autostop criteria */
       /* if (set_autostop_criterion(capture_opts, optarg_str_p) == FALSE) {
            fprintf(stderr,"Invalid or unknown -a flag \"%s\"", optarg_str_p);
            return 1;
        }*/
        break;
#ifdef HAVE_PCAP_REMOTE
    case 'A':
        if (get_auth_arguments(capture_opts, optarg_str_p) == FALSE) {
            fprintf(stderr,"Invalid or unknown -A arg \"%s\"", optarg_str_p);
            return 1;
        }
        break;
#endif
    case 'b':        /* Ringbuffer option */
    /*    capture_opts->multi_files_on = TRUE;
        if (get_ring_arguments(capture_opts, optarg_str_p) == FALSE) {
            fprintf(stderr,"Invalid or unknown -b arg \"%s\"", optarg_str_p);
            return 1;
        }*/
        break;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    case 'B':        /* Buffer size */
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.buffer_size = get_positive_int(optarg_str_p, "buffer size");
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.buffer_size = get_positive_int(optarg_str_p, "buffer size");
        }
        break;
#endif
    case 'c':        /* Capture n packets */
        capture_opts->has_autostop_packets = TRUE;
        capture_opts->autostop_packets = get_positive_int(optarg_str_p, "packet count");
        break;
    case 'f':        /* capture filter */
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            g_free(interface_opts.cfilter);
            interface_opts.cfilter = g_strdup(optarg_str_p);
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            g_free(capture_opts->default_options.cfilter);
            capture_opts->default_options.cfilter = g_strdup(optarg_str_p);
        }
        break;
    case 'H':        /* Hide capture info dialog box */
        break;
    case 'i':        /* Use interface x */
        status = capture_opts_add_iface_opt(capture_opts, optarg_str_p);
        if (status != 0) {
            return status;
        }
        break;
#ifdef HAVE_PCAP_CREATE
    case 'I':        /* Capture in monitor mode */
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.monitor_mode = TRUE;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.monitor_mode = TRUE;
        }
        break;
#endif
    case 'k':        /* Start capture immediately */
        *start_capture = TRUE;
        break;
    /*case 'l':*/    /* Automatic scrolling in live capture mode */
#ifdef HAVE_PCAP_SETSAMPLING
    case 'm':
        if (get_sampling_arguments(capture_opts, optarg_str_p) == FALSE) {
            fprintf(stderr,"Invalid or unknown -m arg \"%s\"", optarg_str_p);
            return 1;
        }
        break;
#endif
    case 'n':        /* Use pcapng format */
        capture_opts->use_pcapng = TRUE;
        break;
    case 'p':        /* Don't capture in promiscuous mode */
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.promisc_mode = FALSE;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.promisc_mode = FALSE;
        }
        break;
    case 'P':        /* Use pcap format */
        capture_opts->use_pcapng = FALSE;
        break;
#ifdef HAVE_PCAP_REMOTE
    case 'r':
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.nocap_rpcap = FALSE;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.nocap_rpcap = FALSE;
        }
        break;
#endif
    case 's':        /* Set the snapshot (capture) length */
        snaplen = get_natural_int(optarg_str_p, "snapshot length");
        /*
         * Make a snapshot length of 0 equivalent to the maximum packet
         * length, mirroring what tcpdump does.
         */
        if (snaplen == 0)
            snaplen = WTAP_MAX_PACKET_SIZE;
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.has_snaplen = TRUE;
            interface_opts.snaplen = snaplen;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.snaplen = snaplen;
            capture_opts->default_options.has_snaplen = TRUE;
        }
        break;
    case 'S':        /* "Real-Time" mode: used for following file ala tail -f */
        capture_opts->real_time_mode = TRUE;
        break;
#ifdef HAVE_PCAP_REMOTE
    case 'u':
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.datatx_udp = TRUE;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.datatx_udp = TRUE;
        }
        break;
#endif
    case 'w':        /* Write to capture file x */


        //status = capture_opts_output_to_pipe(capture_opts->save_file, &capture_opts->output_to_pipe);
        return 1;
    case 'g':        /* enable group read access on the capture file(s) */
        capture_opts->group_read_access = TRUE;
        break;
    case 'y':        /* Set the pcap data link type */
        if (capture_opts->ifaces->len > 0) {
            interface_options interface_opts;

            interface_opts = g_array_index(capture_opts->ifaces, interface_options, capture_opts->ifaces->len - 1);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, capture_opts->ifaces->len - 1);
            interface_opts.linktype = linktype_name_to_val(optarg_str_p);
            if (interface_opts.linktype == -1) {
                fprintf(stderr,"The specified data link type \"%s\" isn't valid",
                           optarg_str_p);
                return 1;
            }
            g_array_append_val(capture_opts->ifaces, interface_opts);
        } else {
            capture_opts->default_options.linktype = linktype_name_to_val(optarg_str_p);
            if (capture_opts->default_options.linktype == -1) {
                fprintf(stderr,"The specified data link type \"%s\" isn't valid",
                           optarg_str_p);
                return 1;
            }
        }
        break;
    default:
        /* the caller is responsible to send us only the right opt's */
       // g_assert_not_reached();
		printf("capture_opts:771  capture_opts_add_opt\n");
    }

    return 0;
}

void
capture_opts_print_if_capabilities(if_capabilities_t *caps, char *name,
                                   gboolean monitor_mode)
{
    GList *lt_entry;
    data_link_info_t *data_link_info;

    if (caps->can_set_rfmon)
        printf("Data link types of interface %s when %sin monitor mode (use option -y to set):\n",
                       name, monitor_mode ? "" : "not ");
    else
        printf("Data link types of interface %s (use option -y to set):\n", name);
    for (lt_entry = caps->data_link_types; lt_entry != NULL;
         lt_entry = g_list_next(lt_entry)) {
        data_link_info = (data_link_info_t *)lt_entry->data;
        printf("  %s", data_link_info->name);
        if (data_link_info->description != NULL)
            printf(" (%s)", data_link_info->description);
        else
            printf(" (not supported)");
        printf("\n");
    }
}

/* Print an ASCII-formatted list of interfaces. */
void
capture_opts_print_interfaces(GList *if_list)
{
    int         i;
    GList       *if_entry;
    if_info_t   *if_info;

    i = 1;  /* Interface id number */
    for (if_entry = g_list_first(if_list); if_entry != NULL;
         if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;
        printf("%d. %s", i++, if_info->name);

        /* Print the description if it exists */
        if (if_info->description != NULL)
            printf(" (%s)", if_info->description);
        printf("\n");
    }
}


void capture_opts_trim_snaplen(capture_options *capture_opts, int snaplen_min)
{
    guint i;
    interface_options interface_opts;

    if (capture_opts->ifaces->len > 0) {
        for (i = 0; i < capture_opts->ifaces->len; i++) {
            interface_opts = g_array_index(capture_opts->ifaces, interface_options, 0);
            capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, 0);
            if (interface_opts.snaplen < 1)
                interface_opts.snaplen = WTAP_MAX_PACKET_SIZE;
            else if (interface_opts.snaplen < snaplen_min)
                interface_opts.snaplen = snaplen_min;
            g_array_append_val(capture_opts->ifaces, interface_opts);
        }
    } else {
        if (capture_opts->default_options.snaplen < 1)
            capture_opts->default_options.snaplen = WTAP_MAX_PACKET_SIZE;
        else if (capture_opts->default_options.snaplen < snaplen_min)
            capture_opts->default_options.snaplen = snaplen_min;
    }
}


gboolean capture_opts_trim_iface(capture_options *capture_opts, const char *capture_device)
{
    GList       *if_list;
    if_info_t   *if_info;
    int         err;
    gchar       *err_str;
    interface_options interface_opts;


    /* Did the user specify an interface to use? */
    if (capture_opts->ifaces->len == 0) {
        /* No - is a default specified in the preferences file? */
        if (capture_device != NULL) {
            /* Yes - use it. */
            interface_opts.name = g_strdup(capture_device);
            /*  We don't set iface_descr here because doing so requires
             *  capture_ui_utils.c which requires epan/prefs.c which is
             *  probably a bit too much dependency for here...
             */
        } else {
            /* No - pick the first one from the list of interfaces. */
            if_list = capture_interface_list(&err, &err_str);
            if (if_list == NULL) {
                switch (err) {

                case CANT_GET_INTERFACE_LIST:
                    fprintf(stderr,"%s", err_str);
                    g_free(err_str);
                    break;

                case NO_INTERFACES_FOUND:
                    fprintf(stderr,"There are no interfaces on which a capture can be done");
                    break;
                }
                return FALSE;
            }
            if_info = (if_info_t *)if_list->data;	/* first interface */
            interface_opts.name = g_strdup(if_info->name);
            /*  We don't set iface_descr here because doing so requires
             *  capture_ui_utils.c which requires epan/prefs.c which is
             *  probably a bit too much dependency for here...
             */
            free_interface_list(if_list);
        }
        if (capture_opts->default_options.descr) {
            interface_opts.descr = g_strdup(capture_opts->default_options.descr);
        } else {
            interface_opts.descr = NULL;
        }
        interface_opts.cfilter = g_strdup(capture_opts->default_options.cfilter);
        interface_opts.snaplen = capture_opts->default_options.snaplen;
        interface_opts.has_snaplen = capture_opts->default_options.has_snaplen;
        interface_opts.linktype = capture_opts->default_options.linktype;
        interface_opts.promisc_mode = capture_opts->default_options.promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)/*нч*/
        interface_opts.buffer_size = capture_opts->default_options.buffer_size;
#endif
        interface_opts.monitor_mode = capture_opts->default_options.monitor_mode;
#ifdef HAVE_PCAP_REMOTE/*нч*/
        interface_opts.src_type = capture_opts->default_options.src_type;
        interface_opts.remote_host = g_strdup(capture_opts->default_options.remote_host);
        interface_opts.remote_port = g_strdup(capture_opts->default_options.remote_port);
        interface_opts.auth_type = capture_opts->default_options.auth_type;
        interface_opts.auth_username = g_strdup(capture_opts->default_options.auth_username);
        interface_opts.auth_password = g_strdup(capture_opts->default_options.auth_password);
        interface_opts.datatx_udp = capture_opts->default_options.datatx_udp;
        interface_opts.nocap_rpcap = capture_opts->default_options.nocap_rpcap;
        interface_opts.nocap_local = capture_opts->default_options.nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING/*нч*/
        interface_opts.sampling_method = capture_opts->default_options.sampling_method;
        interface_opts.sampling_param  = capture_opts->default_options.sampling_param;
#endif
        g_array_append_val(capture_opts->ifaces, interface_opts);
    }

    return TRUE;
}



#ifndef S_IFIFO
#define S_IFIFO	_S_IFIFO
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(mode)  (((mode) & S_IFMT) == S_IFIFO)
#endif

/* copied from filesystem.c */
//static int capture_opts_test_for_fifo(const char *path)
//{
//  ws_statb64 statb;
//
//  if (ws_stat64(path, &statb) < 0)
//    return errno;
//
//  if (S_ISFIFO(statb.st_mode))
//    return ESPIPE;
//  else
//    return 0;
//}

//static gboolean capture_opts_output_to_pipe(const char *save_file, gboolean *is_pipe)
//{
//  int err;
//
//  *is_pipe = FALSE;
//
//  if (save_file != NULL) {
//    /* We're writing to a capture file. */
//    if (strcmp(save_file, "-") == 0) {
//      /* Writing to stdout. */
//      /* XXX - should we check whether it's a pipe?  It's arguably
//         silly to do "-w - >output_file" rather than "-w output_file",
//         but by not checking we might be violating the Principle Of
//         Least Astonishment. */
//      *is_pipe = TRUE;
//    } else {
//      /* not writing to stdout, test for a FIFO (aka named pipe) */
//      err = capture_opts_test_for_fifo(save_file);
//      switch (err) {
//
//      case ENOENT:      /* it doesn't exist, so we'll be creating it,
//                           and it won't be a FIFO */
//      case 0:           /* found it, but it's not a FIFO */
//        break;
//
//      case ESPIPE:      /* it is a FIFO */
//        *is_pipe = TRUE;
//        break;
//
//      default:          /* couldn't stat it              */
//        break;          /* ignore: later attempt to open */
//                        /*  will generate a nice msg     */
//      }
//    }
//  }
//
//  return 0;
//}

//#endif /* HAVE_LIBPCAP */
