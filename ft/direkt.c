#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libsoup/soup.h>
#include <iostream>
#include <capiutils.h>

#include "fax.h"
#include "phone.h"
#include "faxophone.h"
#include "fax_phone.h"
#include "audio.h"
#include "appobject.h"
#include "appobject-emit.h"
#include "logging.h"
#include "net_monitor.h"
#include "routermanager.h"
#include "router.h"
// #include "firmware-04-00.h"
#include "firmware-common.h"
#include <string>
#include <vector>
using namespace std;
#include "direkt.h"


fbcl::fbcl()
{
  sid=si0="0000000000000000";
//  usr=".........";
//  pwd="..........";
  host="fritz.box";//"192.168.178.1";
  stim=0;
  eingel=0;
}

#ifdef false
int fbcl::loadj()
{
  if (!eingel) return 0;
  soup_session=soup_session_new_with_options(SOUP_SESSION_TIMEOUT,5,NULL);
  url="http://"+host+"/fon_num/foncalls_list.lua";
  msg=soup_form_request_new(SOUP_METHOD_GET,url.c_str(),"sid",sid.c_str(),"csv","",NULL);
  soup_session_send_message(soup_session,msg);
  if (msg->status_code!=200) {
    printf("%s(): Received Status code: %d\n",__FUNCTION__ ,msg->status_code);
    g_object_unref(msg);
    return 0;
  } else {
    data=msg->response_body->data;
    printf("%s\n",data);
    return 1;
  }
  g_object_unref(msg);
  g_object_unref(soup_session);
}

const std::string nix="";

std::string xmlex(std::string data,std::string lim,std::string lim2/*=nix*/,size_t *p2p/*=0*/)
{
  size_t p1=data.find("<"+lim+">",p2p?*p2p:0);
  if (p1!=std::string::npos) {
    p1+=lim.length()+2;
    size_t p2=data.find("</"+(lim2.empty()?lim:lim2)+">",p1);
    if (p2!=std::string::npos) {
      if (p2p) *p2p=p2;
      return data.substr(p1,p2-p1);
    }
  }
  return "";
}

int fbcl::fb_check_login_blocked()
{
	int result;
	g_debug("%s(): session_id %s", __FUNCTION__, sid.c_str());
	result = (sid!=si0);
	if (!result) {
		const gchar *blocktime = xmlex(data,"BlockTime").c_str();
		if (blocktime) {
			g_debug("%s(): Block Time = %s", __FUNCTION__, blocktime);
			g_debug("%s(): Block Time = %d", __FUNCTION__, atoi(blocktime));
			g_usleep(atoi(blocktime) * G_USEC_PER_SEC);

			if (atoi(blocktime)) {
        g_timer_destroy(stim);
				stim = NULL;
			}
		}
	}
	return result;
} // int fbcl::fb_check_login_blocked()
#endif

#ifdef false
/**
 * \brief Compute md5 sum of input string
 * \param input - input string
 * \return md5 in hex or NULL on error
 */
static inline gchar *md5(const char *input)
{
	GError *error = NULL;
	gchar *ret = NULL;
	gsize written;
	gchar *bin = g_convert(input, -1, "UTF-16LE", "UTF-8", NULL, &written, &error);

	if (error == NULL) {
		ret = g_compute_checksum_for_string(G_CHECKSUM_MD5, (gchar *) bin, written);
		g_free(bin);
	} else {
		g_debug("Error converting utf8 to utf16: '%s'", error->message);
		g_error_free(error);
	}

	return ret;
}

void fbcl::fb_login_05_50()
{
  if (stim && g_timer_elapsed(stim,NULL)<9*60) {
    eingel=1;
    return;
  } else {
    if (!stim) {
      stim=g_timer_new();
      g_timer_start(stim);
    } else {
      g_timer_reset(stim);
    }
  }
  soup_session=soup_session_new_with_options(SOUP_SESSION_TIMEOUT,5,NULL);
  url="http://"+host+"/login_sid.lua";
  msg = soup_message_new(SOUP_METHOD_GET, g_strdup(url.c_str()));
  soup_session_send_message(soup_session,msg);
  if (msg->status_code!=200) {
    printf("%s(): Status code: %d\n",__FUNCTION__ ,msg->status_code);
    g_timer_destroy(stim);
    stim=NULL;
    eingel=0;
    return;
  } else {
    data=msg->response_body->data;
    read=msg->response_body->length;
    printf("data: %s\n",data);
    sid=xmlex(data,"SID");
    eingel=fb_check_login_blocked();
    if (sid==si0) {
      std::string chal=xmlex(data,"Challenge");
      printf("%s\n",sid.c_str());
      printf("%s\n",chal.c_str());
      g_object_unref(msg);
      gchar *dots=make_dots(g_strdup(pwd.c_str()));
      gchar *md5str=md5((chal+"-"+dots).c_str());
      std::string resp=chal+"-"+md5str;
      g_free(md5str);
      g_free(dots);
      msg=soup_form_request_new(SOUP_METHOD_POST,url.c_str(),"username",usr.c_str(),"response",resp.c_str(),NULL);
      soup_session_send_message(soup_session,msg);
      if (msg->status_code!=200) {
        printf("%s(): Status code: %d\n",__FUNCTION__ ,msg->status_code);
        g_object_unref(msg);
        g_timer_destroy(stim);
        stim=NULL;
        eingel=0;
        return;
      } else {
        data=msg->response_body->data;
        read=msg->response_body->length;
        printf("data: %s\n",data);
        sid=xmlex(data,"SID");
        printf("%s\n",sid.c_str());
        eingel=fb_check_login_blocked();
      }
    }
    printf("%s\n",sid.c_str());
  }
  g_object_unref(msg);
  g_object_unref(soup_session);
}



static gint log_level = 0;

static void (*logging)(gint level, const gchar *text) = NULL;

/**
 * \brief Dump spandsp messages
 * \param level spandsp loglevel
 * \param text message text
 */
static void spandsp_msg_log(gint level, const gchar *text)
{
	g_debug("%s", text);
}

/**
 * \brief Get total pages in TIFF file
 * \param file filename
 * \return number of pages
 */
static int get_tiff_total_pages(const char *file)
{
	TIFF *tiff_file;
	int max;

	if ((tiff_file = TIFFOpen(file, "r")) == NULL) {
		return -1;
	}

	max = 0;
	while (TIFFSetDirectory(tiff_file, (tdir_t) max)) {
		max++;
	}

	TIFFClose(tiff_file);

	return max;
}

// aus fax.c
gint spandsp_init(const gchar *tiff_file, gboolean sending, gchar modem, gchar ecm, const gchar *lsi, const gchar *local_header_info, struct capi_connection *connection);

/**
 * \brief Send Fax
 * \param tiff_file The Tiff file to send
 * \param modem 0-3 (2400-14400)
 * \param ecm Error correction mode (on/off)
 * \param controller The controller for sending the fax
 * \param src_no MSN
 * \param trg_no Target fax number
 * \param lsi Fax ident
 * \param local_header_info Fax header line
 * \param call_anonymous Send fax anonymous
 * \return error code
 */
struct capi_connection *fax_send_hier(gchar *tiff_file, gint modem, gint ecm, gint controller, gint cip, const gchar *src_no, const gchar *trg_no, const gchar *lsi, const gchar *local_header_info, gint call_anonymous)
{
  printf("Beginn fax_send: %s, %d, %d, %d, %d, %s, %s, %s, %s, %d\n",tiff_file,modem,ecm,controller,cip,src_no,trg_no,lsi,local_header_info,call_anonymous);
	struct fax_status *status;
	struct capi_connection *connection;

	g_debug("tiff: %s, modem: %d, ecm: %s, controller: %d, src: %s, trg: %s, ident: %s, header: %s, anonymous: %d)", tiff_file, modem, ecm ? "on" : "off", controller, src_no, trg_no, (lsi != NULL ? lsi : "(null)"), (local_header_info != NULL ? local_header_info : "(null)"), call_anonymous);

	//status = g_slice_new0(struct fax_status);
	status = (fax_status*)malloc(sizeof(struct fax_status));
	memset(status, 0, sizeof(struct fax_status));

	status->phase = IDLE;
	status->error_code = -1;
	status->sending = 1;
	status->manual_hookup = 0;
	status->modem = modem;
	status->ecm = ecm;
	snprintf(status->header, sizeof(status->header), "%s", local_header_info);
	snprintf(status->ident, sizeof(status->ident), "%s", lsi);
	snprintf(status->src_no, sizeof(status->src_no), "%s", src_no);
	snprintf(status->trg_no, sizeof(status->trg_no), "%s", trg_no);
	snprintf(status->tiff_file, sizeof(status->tiff_file), "%s", tiff_file);

	connection = capi_call(controller, src_no, trg_no, (guint) call_anonymous, SESSION_FAX, cip, 1, 1, 0, NULL, NULL, NULL);
	if (connection) {
		status->connection = connection;
		connection->priv = status;
		spandsp_init(status->tiff_file, TRUE, status->modem, status->ecm, status->ident, status->header, connection);
	}

	return connection;
}
#endif

gboolean faxophone_connect(gpointer user_data);

// 4.1.18, aus fax_phone.c
struct capi_connection *active_capi_connection = NULL;

// 4.1.18, aus connection.c
/** Global connect list pointer */
static GSList *connection_list = NULL;
/**
 * \brief Find connection entry by number
 * \param remote_number connection number
 * \return connection pointer or NULL on error
 */
struct connection *connection_find_by_number(const gchar *remote_number)
{
	GSList *list = connection_list;
	struct connection *connection;

	while (list) {
		connection = (struct connection*)list->data;

		if (!strcmp(connection->remote_number, remote_number)) {
			return connection;
		}

		list = list->next;
	}

	return NULL;
}

/**
 * \brief Connection ring handler
 * \param connection capi connection structure
 */
gboolean connection_ring_idle(gpointer data)
{
	struct capi_connection *capi_connection = (struct capi_connection*)data;
	struct connection *connection;

	active_capi_connection = capi_connection;

	g_debug("connection_ring() src %s trg %s", capi_connection->source, capi_connection->target);
	connection = connection_find_by_number(capi_connection->source);
#if ACCEPT_INTERN
	if (!connection && !strncmp(capi_connection->source, "**", 2)) {
		connection = connection_add_call(981, CONNECTION_TYPE_INCOMING, capi_connection->source, capi_connection->target);
	}
#endif

	g_debug("connection_ring() connection %p", connection);
	if (connection) {
		g_debug("connection_ring() set capi_connection %p", capi_connection);
		connection->priv = capi_connection;

		emit_connection_notify(connection);
	}

	return G_SOURCE_REMOVE;
}

void connection_ring(struct capi_connection *capi_connection)
{
	g_idle_add(connection_ring_idle, capi_connection);
}


/**
 * \brief Connection code handler
 * \param connection capi connection structure
 * \param code dtmf code
 */
void connection_code(struct capi_connection *connection, gint code)
{
	g_debug("connection_code(): code 0x%x", code);
}

/**
 * \brief Connection status handlers - emits connection-status signal
 * \param connection capi connection structure
 * \param status status code
 */
void connection_status(struct capi_connection *connection, gint status)
{
	emit_connection_status(status, connection);
}

gboolean connection_established_idle(gpointer data)
{
	struct capi_connection *connection = (struct capi_connection*)data;

	emit_connection_established(connection);

	return G_SOURCE_REMOVE;
}

void connection_established(struct capi_connection *connection)
{
	g_idle_add(connection_established_idle, connection);
}

gboolean connection_terminated_idle(gpointer data)
{
	struct capi_connection *connection = (struct capi_connection*)data;

	emit_connection_terminated(connection);

	return G_SOURCE_REMOVE;
}

void connection_terminated(struct capi_connection *connection)
{
	g_idle_add(connection_terminated_idle, connection);
}


#ifdef false
gboolean fbcl::waehle(/*struct profile *profile, */gint port, const gchar *number)
{
	gboolean ret;
	/*
	gchar *target = call_canonize_number(number);
	ret = active_router->dial_number(profile, port, target);
	g_free(target);
	*/
  ret=fritzbox_present();
	// fprintf("ret: %i\n",ret);
	exit(0);
	//active_router->dial_number(profile, port, target);

	return ret;
}
#endif

static struct session *session = NULL;
struct session_handlers session_handlers = {
	audio_open, /* audio_open */
	audio_read, /* audio_read */
	audio_write, /* audio_write */
	audio_close, /* audio_close */

	connection_established, /* connection_established */
	connection_terminated, /* connection_terminated */
	connection_ring, /* connection_ring */
	connection_code, /* connection_code */
	connection_status, /* connection_status */
};
// aus fax_phone.c
/**
 * \brief Faxophone connect
 * \param user_data faxophone plugin pointer
 * \return error code
 */
gboolean fbcl::faxophone_connect_hier()
{
//	struct profile *profile = profile_get_active();
	gboolean retry = TRUE;
	gchar* _host=(gchar*)"fritz.box"; // router_get_host(profile);
	printf("Beginn faxophone_connect_hier, host: %s, phone-controller: %i\n",_host,controller);
again:
	session = faxophone_init(&session_handlers, _host, controller + 1);
	if (!session && retry) {
		// Maybe the port is closed, try to activate it and try again 
#ifdef false
		waehle(PORT_ISDN1, "#96*3*");
		g_usleep(G_USEC_PER_SEC * 2);
#endif
		retry = FALSE;
		goto again;
	}
	return session != NULL;
}

// aus main_cli.c
#include <config.h>
#undef _
#define _(x) x
static gboolean debug = FALSE;
static gboolean journal = FALSE;
static gboolean sendfax = FALSE;
static gboolean call = FALSE;
static gchar *file_name = NULL;
static gchar *number = NULL;
static GOptionEntry entries[] = {
	{"debug", 'd', 0, G_OPTION_ARG_NONE, &debug, "Enable debug messages", NULL},
	{"journal", 'j', 0, G_OPTION_ARG_NONE, &journal, "Prints journal", NULL},
	{"sendfax", 's', 0, G_OPTION_ARG_NONE, &sendfax, "Send fax", NULL},
	{"file", 'f', 0, G_OPTION_ARG_STRING, &file_name, "PDF/PS file", NULL},
	{"number", 'n', 0, G_OPTION_ARG_STRING, &number, "Remote phone number", NULL},
	{"call", 'c', 0, G_OPTION_ARG_NONE, &call, "Call number", NULL},
	{NULL}
};
/** Internal main loop */
GMainLoop *main_loop = NULL;
static gboolean success = FALSE;

/**
 * \brief FAX connection status - show status message
 * \param object appobject
 * \param status fax connection status
 * \param connection capi connection pointer
 * \param user_data user data pointer (NULL)
 */
void fax_connection_status_cb(AppObject *object, gint status, struct capi_connection *connection, gpointer user_data)
{
	struct fax_status *fax_status;
	gchar buffer[256];
	printf("Begin fax_connection_status_cb\n");

	fax_status = (struct fax_status*)connection->priv;
	if (!fax_status) {
		g_warning("No status available");
		return;
	}

	if (!status && !fax_status->done) {
		switch (fax_status->phase) {
		case PHASE_B:
			g_debug("Ident: %s", fax_status->remote_ident);
			snprintf(buffer, sizeof(buffer), "%d/%d", fax_status->page_current, fax_status->page_total);

			g_message(_("Transfer starting:"));
			g_message("%s", buffer);
			break;
		case PHASE_D:
			snprintf(buffer, sizeof(buffer), "%d", fax_status->page_current);
			g_message(_("Transferring page"));
			g_message("%s", buffer);
			break;
		case PHASE_E:
			if (!fax_status->error_code) {
				g_message("%s", "Fax transfer successful");
				success = TRUE;
			} else {
				g_message("%s", "Fax transfer failed");
				success = FALSE;
			}
			phone_hangup(connection);
			fax_status->done = TRUE;
			g_main_loop_quit(main_loop);
			break;
		default:
			g_debug("Unhandled phase (%d)", fax_status->phase);
			break;
		}
	} else if (status == 1) {
		float percentage = 0.0f;
		gchar text[6];
		int percent = 0;
		static int old_percent = 0;

		percentage = (float) fax_status->bytes_sent / (float) fax_status->bytes_total;

		if (percentage > 1.0f) {
			percentage = 1.0f;
		}

		percent = percentage * 100;
		if (old_percent == percent) {
			return;
		}
		old_percent = percent;

		snprintf(text, sizeof(text), "%d%%", percent);
		g_message("Transfer at %s", text);
	}
}

/**
 * \brief CAPI connection established callback - just print message
 * \param object appobject
 * \param connection capi connection pointer
 * \param user_data user data pointer (NULL)
 */
static void capi_connection_established_cb(AppObject *object, struct capi_connection *connection, gpointer user_data)
{
	g_message(_("Connected"));
}

/**
 * \brief CAPI connection terminated callback - just print message
 * \param object appobject
 * \param connection capi connection pointer
 * \param user_data user data pointer (NULL)
 */
static void capi_connection_terminated_cb(AppObject *object, struct capi_connection *connection, gpointer user_data)
{
	g_message(_("Disconnected"));
	g_main_loop_quit(main_loop);
}

// aus routermanager.c
/**
 * \brief Create routermanager
 * \param debug enable debug output
 * \return TRUE on success, FALSE on error
 */
gboolean routermanager_new_hier(gboolean debug, GError **error)
{
	gchar *dir;

#if !GLIB_CHECK_VERSION(2, 36, 0)
	/* Init g_type */
	g_type_init();
#endif

	/* Init directory path */
	// init_directory_paths();

	/* Initialize logging system */
	log_init(debug);

	/* Say hello */
	g_debug("%s %s", PACKAGE_NAME, PACKAGE_VERSION);

	/* Create routermanager data & cache directory */
	dir = g_build_filename(g_get_user_data_dir(), "routermanager", NULL);
	g_mkdir_with_parents(dir, 0700);
	g_free(dir);

	dir = g_build_filename(g_get_user_cache_dir(), "routermanager", NULL);
	g_mkdir_with_parents(dir, 0700);
	g_free(dir);

	/* Create main app object (signals) */
	app_object = app_object_new();
	g_assert(app_object != NULL);

	return TRUE;
}
/**
 * \brief Initialize routermanager
 * \return TRUE on success, FALSE on error
 */
gboolean routermanager_init_hier(GError **error)
{
	/* Init filter */
	// filter_init();

	/* Init fax printer */
	/*
	if (!fax_printer_init(error)) {
		return FALSE;
	}
	*/

	/* Initialize network */
	net_init();

	/* Load plugins depending on ui (router, audio, address book, reverse lookup...) */
	// routermanager_plugins_add_search_path(get_plugin_dir());

	/* Initialize plugins */
	// plugins_init();

	/* Check password manager */
	/*
	if (!password_manager_get_plugins()) {
		g_set_error(error, RM_ERROR, RM_ERROR_ROUTER, "%s", "No password manager plugins active");
		return FALSE;
	}
	*/

	/* Initialize router */
	/*
	if (!router_init()) {
		g_set_error(error, RM_ERROR, RM_ERROR_ROUTER, "%s", "Failed to initialize router");
		return FALSE;
	}
	*/

	/* Initialize profiles */
	// profile_init();

	/* Initialize network monitor */
	// net_monitor_init();

	return TRUE;
}

// #define FIRMWARE_IS(major, minor) (((profile->router_info->maj_ver_id == major) && (profile->router_info->min_ver_id >= minor)) || (profile->router_info->maj_ver_id > major))
int fbcl::FIRMWARE_IS(int vmaj,int vmin)
{
  return (maj_ver_id==vmaj&&min_ver_id>=vmin)||maj_ver_id>vmaj;
}

int main(int argc, char** argv)
{
	GError *error = NULL;
	GOptionContext *context;
	gchar *tiff = NULL;
	int ret = 0;

#if !GLIB_CHECK_VERSION(2, 36, 0)
	/* Init g_type */
	g_type_init();
#endif

	context = g_option_context_new("-");
	g_option_context_add_main_entries(context, entries, GETTEXT_PACKAGE);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_print("option parsing failed: %s\n", error->message);
		exit(1);
	}
	routermanager_new(debug, NULL);
	/* Initialize routermanager */

	routermanager_init_hier(NULL);
	//faxophone_setup();
	static gconstpointer net_event;
//	net_event = net_add_event(faxophone_connect_hier, faxophone_disconnect, NULL);

	/* Only show messages >= INFO */
	log_set_level(G_LOG_LEVEL_INFO);

//  fb.loadj();
//  fb.fb_get_settings_05_50();
		g_signal_connect(app_object, "connection-status", G_CALLBACK(fax_connection_status_cb), NULL);
		g_signal_connect(app_object, "connection-established", G_CALLBACK(capi_connection_established_cb), NULL);
		g_signal_connect(app_object, "connection-terminated", G_CALLBACK(capi_connection_terminated_cb), NULL);

	system("gs -q -dNOPAUSE -dSAFER -dBATCH -sDEVICE=tiffg4 -sPAPERSIZE=a4 -dFIXEDMEDIA -r204x98 -sOutputFile=t0.pdf.tif ~/rogerj/wand/t0.pdf");
	// gpointer user_data;
	fbcl fb;
	if(argc>1) fb.controller=atoi(argv[1]);
	fb.faxophone_connect_hier();
	// exit(0);
	// aus fax_dial
	struct capi_connection * conn=fax_send((gchar*)"t0.pdf.tif",/*modem,3=14400*/3,/*ecm*/1,/*controller*/5,/*cip,4=speech,0x11=fax,geht beides*/4,
			    (gchar*)"6150166",(gchar*)"619712",/*lsi*/(gchar*)"+496150166",/*local_header_info*/(gchar*)"G.Schade",/*return error code*/0);
	/* Create and start g_main_loop */

	printf("Vor main_loop\n");
  // fax_transfer
	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);

	/* Shutdown routermanager */
	//routermanager_shutdown();
	/* Destroy app_object */
	g_clear_object(&app_object);

	/* Shutdown logging */
	log_shutdown();

	faxophone_close(TRUE);
}
