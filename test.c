#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <libsoup/soup.h>
#include <json-glib/json-glib.h>
#include <libintl.h> // für gettext
#include <libxml/parser.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include <string.h>
#include <config.h>
#include <errno.h>

//#include <glib.h>
//#include <libroutermanager/file.h>
// fuer _cstruct, aus capiutils.h über capi20.h
struct session *session=NULL;
#include <libroutermanager/libfaxophone/faxophone.h>
#include <libroutermanager/appobject.h>
#include <libroutermanager/appobject-emit.h>
#include <libroutermanager/filter.h>
#include <libroutermanager/routermanager.h>
//#include <libroutermanager/fax_printer.h>
gboolean fax_printer_init(GError **error);
#include <libpeas/peas.h>
#include <libroutermanager/plugins.h>
#include <libgupnp/gupnp.h>
#include <libgupnp/gupnp-device-info.h>

#include <libroutermanager/router.h>
//#include <libroutermanager/connection.h>


//#include <libroutermanager/libfaxophone/fax.h>
//#include <libroutermanager/libfaxophone/sff.h>

#ifndef EMPTY_STRING
#define EMPTY_STRING(x) (!(x) || !strlen(x))
#endif

void fdebug( const char* format, ... )
{
  va_list arglist;

  printf( "Debug: " );
  va_start( arglist, format );
  vprintf( format, arglist );
  va_end( arglist );
  printf("\n");
}

SoupSession *soup_session;
static GMainLoop *loop;
static gboolean debug, head, quiet;
static const gchar *output_file_path = NULL;

static void finished (SoupSession *soup_session, SoupMessage *msg, gpointer loop)
{
	g_main_loop_quit ((GMainLoop*)loop);
}

const char *geturl(const char *url)
{
	SoupMessage *msg=soup_message_new ("GET", url);
	soup_message_set_flags(msg, SOUP_MESSAGE_NO_REDIRECT);
  soup_session_send_message (soup_session, msg);
  if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
    return msg->response_body->data;
  return "";
} // gchar *geturl(const char *url)

static void get_url (const char *url)
{
	const char *name;
	SoupMessage *msg;
	const char *header;
	FILE *output_file = NULL;

	msg = soup_message_new (head ? "HEAD" : "GET", url);
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);

	if (loop) {
		g_object_ref (msg);
		soup_session_queue_message (soup_session, msg, finished, loop);
		g_main_loop_run (loop);
	} else
		soup_session_send_message (soup_session, msg);

	name = soup_message_get_uri (msg)->path;

	if (!debug) {
		if (msg->status_code == SOUP_STATUS_SSL_FAILED) {
			GTlsCertificateFlags flags;

			if (soup_message_get_https_status (msg, NULL, &flags))
				g_print ("%s: %d %s (0x%x)\n", name, msg->status_code, msg->reason_phrase, flags);
			else
				g_print ("%s: %d %s (no handshake status)\n", name, msg->status_code, msg->reason_phrase);
		} else if (!quiet || SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code))
			g_print ("%s: %d %s\n", name, msg->status_code, msg->reason_phrase);
	}

	if (SOUP_STATUS_IS_REDIRECTION (msg->status_code)) {
		header = soup_message_headers_get_one (msg->response_headers,
						       "Location");
		if (header) {
			SoupURI *uri;
			char *uri_string;

			if (!debug && !quiet)
				g_print ("  -> %s\n", header);

			uri = soup_uri_new_with_base (soup_message_get_uri (msg), header);
			uri_string = soup_uri_to_string (uri, FALSE);
			get_url (uri_string);
			g_free (uri_string);
			soup_uri_free (uri);
		}
	} else if (!head && SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		if (output_file_path) {
			output_file = fopen (output_file_path, "w");
			if (!output_file)
				g_printerr ("Error trying to create file %s.\n", output_file_path);
		} else if (!quiet)
			output_file = stdout;

		if (output_file) {
			fwrite (msg->response_body->data,
				1,
				msg->response_body->length,
				output_file);

			if (output_file_path)
				fclose (output_file);
		}
	}
	g_object_unref (msg);
} // static void get_url (const char *url)

GObject *app_object = NULL;
guint app_object_signals[ACB_MAX] = { 0 };

void emit_authenticate(struct auth_data *auth_data)
{
	g_signal_emit(app_object, app_object_signals[ACB_AUTHENTICATE], 0, auth_data);
}

class router_icl {
  public:
	gchar *host;
	gchar *user;
	gchar *password;
	gchar *name;
	gchar *version;
	gchar *serial;
	gchar *session_id;
	gchar *lang;
	gchar *annex;
  gchar *ftpusr;
  gchar *ftppwd;

	/* Extend */
	gint box_id;
	gint maj_ver_id;
	gint min_ver_id;
	GTimer *session_timer;

  const gchar *lkz;
  const gchar *lkz_prefix;
  const gchar *okz;
  const gchar *okz_prefix;
  const gchar *port_str;
  gint port;
  const gchar *fax_ident;
  const gchar *storage;
  const gchar *fax_msn;
  const gchar *formated_number;
  const gchar *pname[PORT_MAX];
  const gchar *name_analog[3];
  const gchar *iname[3];
  const gchar *name_isdn[3];
  const gchar *dname[10];
  const gchar *intern[10];
  gchar ** numbers;
  gchar ** nname;
  const gchar *dialport;
  gint phone_port;
  const gchar *tamstickstr;
  gint tamstick;
  gint faxcontroller;
  gint phonecontroller;
  gchar *faxheaders;
  gchar *faxvolume;
  gchar *faxreportdir;
  public:
  router_icl();
//	GSettings *settings;
} ri;

router_icl::router_icl()
{
 name=0;
 version=0;
 session_timer=0;
 lkz=0;
 lkz_prefix=0;
 okz=0;
 okz_prefix=0;
 port_str=0;
 port=0;
 fax_ident=0;
 storage=0;
 fax_msn=0;
 formated_number=0;
 for(int i=0;i<sizeof pname/sizeof *pname;i++) pname[i]=0;
 for(int i=0;i<sizeof name_analog/sizeof *name_analog;i++) name_analog[i]=0;
 for(int i=0;i<sizeof iname/sizeof *iname;i++) iname[i]=0;
 for(int i=0;i<sizeof name_isdn/sizeof *name_isdn;i++) name_isdn[i]=0;
 for(int i=0;i<sizeof dname/sizeof *dname;i++) dname[i]=0;
 for(int i=0;i<sizeof intern/sizeof *intern;i++) intern[i]=0;
 numbers=0;
 nname=0;
 dialport=0;
 phone_port=0;
 tamstickstr=0;
 tamstick=0;
 faxcontroller=0;
 phonecontroller=0;
 faxheaders=0;
 faxvolume=0;
}

struct voice_data {
	/* 0 */
	gint header;
	/* 4 */
	gint index;
	/* 8 (2=own message, 3=remote message) */
	gint type;
	/* 12 */
	guint sub_type;
	/* 16 */
	guint size;
	/* 20 */
	guint duration;
	/* 24 */
	guint status;
	/* 28 */
	guchar tmp0[24];
	/* 52 */
	gchar remote_number[54];
	/* 106 */
	gchar tmp1[18];
	/* 124 */
	gchar file[32];
	/* 151 */
	gchar path[128];
	/* 279 */
	guchar day;
	guchar month;
	guchar year;
	guchar hour;
	guchar minute;
	guchar tmp2[31];
	gchar local_number[24];
	gchar tmp3[4];
};

struct voice_box {
	gsize len;
	gpointer data;
};

static struct voice_box voice_boxes[5];

static void network_authenticate_cb(SoupSession *session, SoupMessage *msg, SoupAuth *auth, gboolean retrying, gpointer user_data)
{
	struct auth_data *auth_data;
//	struct profile *profile = profile_get_active();
	//const gchar *user;
	//const gchar *password;
  router_icl *ri=(router_icl*)user_data;

	fdebug("%s(): retrying: %d, status code: %d == %d", __FUNCTION__, retrying, msg->status_code, SOUP_STATUS_UNAUTHORIZED);
	if (msg->status_code != SOUP_STATUS_UNAUTHORIZED) {
		return;
	}

//	fdebug("%s(): called with profile %p", __FUNCTION__, profile); if (!profile) { return; }

	soup_session_pause_message(session, msg);
	/* We need to make sure the message sticks around when pausing it */
	g_object_ref(msg);

	// user = g_settings_get_string(profile->settings, "auth-user");
	// password = g_settings_get_string(profile->settings, "auth-password");

	if (!retrying && !EMPTY_STRING(ri->user) && !EMPTY_STRING(ri->password)) {
		fdebug("%s(): Already configured...", __FUNCTION__);
		soup_auth_authenticate(auth, ri->user, ri->password);

		soup_session_unpause_message(session, msg);
	} else {
		auth_data = g_slice_new0(struct auth_data);

		auth_data->msg = msg;
		auth_data->auth = auth;
		auth_data->session = session;
		auth_data->retry = retrying;
		auth_data->username = g_strdup(ri->user);
		auth_data->password = g_strdup(ri->password);

		emit_authenticate(auth_data);
	}
}

gboolean net_init(router_icl *ri)
{
	soup_session = soup_session_new_with_options(SOUP_SESSION_TIMEOUT, 5, NULL);

	g_signal_connect(soup_session, "authenticate", G_CALLBACK(network_authenticate_cb), ri/*soup_session*/);

	return soup_session != NULL;
}

/**
 * \brief Deinitialize network infrastructure
 */
void net_shutdown(void)
{
	g_clear_object(&soup_session);
}


gchar *g_strcasestr(const gchar *haystack, const gchar *needle)
{
	size_t n = strlen(needle);

	if (!haystack || !needle) {
		return NULL;
	}

	for (; *haystack; haystack++) {
		if (g_ascii_strncasecmp(haystack, needle, n) == 0) {
			return (gchar *) haystack;
		}
	}

	return NULL;
}

gboolean fritzbox_present_04_00(struct router_icl *ri)
{
	SoupMessage *msg;
	const gchar *data;
	gchar *url;
	gboolean ret = FALSE;
	gsize read;

  printf("Versuch 04_00\n");
	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host);
	msg = soup_message_new(SOUP_METHOD_GET, url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		g_warning("Could not load 04_00 present page (Error: %d)", msg->status_code);
		g_object_unref(msg);
		g_free(url);

		return ret;
	}

	data = msg->response_body->data;
	read = msg->response_body->length;

//	log_save_data("fritzbox-04_00-present.html", data, read);
	g_assert(data != NULL);

	if (g_strcasestr(data, "fritz!box")) {
		ret = TRUE;

		ri->name = g_strdup("FRITZ!Box");
		ri->version = g_strdup(">= x.4.0");
		ri->lang = g_strdup("de");
		ri->annex = g_strdup("");

		/* This is a fritz!box router, but which version.... */
		ri->box_id = 0;
		ri->maj_ver_id = 4;
		ri->min_ver_id = 0;
		ri->serial = g_strdup("Type Login");
	} else {
		ret = FALSE;
	}

	g_object_unref(msg);
	g_free(url);

	return ret;
}

gchar *xml_extract_tag(const gchar *data, gchar *tag)
{
	gchar *regex_str = g_strdup_printf("<%s>[^<]*</%s>", tag, tag);
	GRegex *regex = NULL;
	GError *error = NULL;
	GMatchInfo *match_info;
	gchar *entry = NULL;
	gint tag_len = strlen(tag);

	regex = g_regex_new(regex_str, (GRegexCompileFlags)0, (GRegexMatchFlags)0, &error);
	g_assert(regex != NULL);

	g_regex_match(regex, data, (GRegexMatchFlags)0, &match_info);

	while (match_info && g_match_info_matches(match_info)) {
		gint start;
		gint end;
		gboolean fetched = g_match_info_fetch_pos(match_info, 0, &start, &end);

		if (fetched == TRUE) {
			gint entry_size = end - start - 2 * tag_len - 5;
			entry = (gchar*)g_malloc0(entry_size + 1);
			strncpy(entry, data + start + tag_len + 2, entry_size);
			break;
		}

		if (g_match_info_next(match_info, NULL) == FALSE) {
			break;
		}
	}

	g_match_info_free(match_info);
	g_free(regex_str);

	return entry;
}

gboolean fritzbox_present(struct router_icl *ri)
{
	SoupMessage *msg;
	gsize read;
	const gchar *data;
	gchar *name;
	gchar *version;
	gchar *lang;
	gchar *serial;
	gchar *url;
	gchar *annex;
	gboolean ret = FALSE;
	SoupLogger *logger = NULL;

	if (ri->name != NULL) {
		g_free(ri->name);
    ri->name=0;
	}

	if (ri->version != NULL) {
		g_free(ri->version);
		ri->version=0;

	}

	if (ri->session_timer != NULL) {
		g_timer_destroy(ri->session_timer);
		ri->session_timer = NULL;
	}
	url = g_strdup_printf("http://%s/jason_boxinfo.xml", ri->host);
  printf("Nr 1 fritzbox_present, url: '%s'\n",url);
	msg = soup_message_new(SOUP_METHOD_GET, url);

// GSchade
#ifdef asynch
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
  printf("Nr 31 fritzbox_present\n");
		g_object_ref (msg);
  printf("Nr 32 fritzbox_present\n");
		soup_session_queue_message (soup_session, msg, finished, loop);
  printf("Nr 33 fritzbox_present\n");
	loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run (loop);
  printf("Nr 34 fritzbox_present\n");
#else
	if (msg->status_code != 200) {
		g_object_unref(msg);
  }
  msg = soup_message_new(SOUP_METHOD_GET, url);
	SoupSession *session = (SoupSession*)g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_CONTENT_DECODER,
//				SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_COOKIE_JAR,
				SOUP_SESSION_USER_AGENT, "get ",
				SOUP_SESSION_ACCEPT_LANGUAGE_AUTO, TRUE,
				NULL);
  logger = soup_logger_new (SOUP_LOGGER_LOG_BODY, -1);
  net_shutdown(); net_init(ri);
  soup_session_add_feature (soup_session, SOUP_SESSION_FEATURE (logger));
  g_object_unref (logger);
  soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
  soup_session_send_message(soup_session, msg);
      g_object_unref (session);
#endif
	if (msg->status_code != 200) {
		g_object_unref(msg);
		g_free(url);

		if (msg->status_code == 404) {
			ret = fritzbox_present_04_00(ri);
		} else {
			g_warning("Could not read boxinfo file (Error: %d, %s)", msg->status_code, soup_status_get_phrase(msg->status_code));
		}

		return ret;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	// log_save_data("fritzbox-present.html", data, read);
	g_return_val_if_fail(data != NULL, FALSE);

	name = xml_extract_tag(data, (gchar*)"j:Name");
	version = xml_extract_tag(data, (gchar*)"j:Version");
	lang = xml_extract_tag(data, (gchar*)"j:Lang");
	serial = xml_extract_tag(data, (gchar*)"j:Serial");
	annex = xml_extract_tag(data, (gchar*)"j:Annex");

	g_object_unref(msg);
	g_free(url);

	if (name && version && lang && serial && annex) {
		gchar **split;

		ri->name = g_strdup(name);
		ri->version = g_strdup(version);
		ri->lang = g_strdup(lang);
		ri->serial = g_strdup(serial);
		ri->annex = g_strdup(annex);

		/* Version: Box.Major.Minor(-XXXXX) */

		split = g_strsplit(ri->version, ".", -1);

		ri->box_id = atoi(split[0]);
		ri->maj_ver_id = atoi(split[1]);
		ri->min_ver_id = atoi(split[2]);

		g_strfreev(split);
		ret = TRUE;
	} else {
		g_warning("name, version, lang or serial not valid");
	}

	g_free(annex);
	g_free(serial);
	g_free(lang);
	g_free(version);
	g_free(name);

	return ret;
}

#define FIRMWARE_IS(major, minor) (((ri->maj_ver_id == major) && (ri->min_ver_id >= minor)) || (ri->maj_ver_id > major))
static gboolean fritzbox_check_login_blocked(const gchar *data, struct router_icl *ri)
{
	gboolean result;

	fdebug("%s(): session_id %s", __FUNCTION__, ri->session_id);
	result = !!strcmp(ri->session_id, "0000000000000000");
	if (!result) {
		const gchar *blocktime = xml_extract_tag(data, (gchar*)"BlockTime");
		if (blocktime) {
			fdebug("%s(): Block Time = %s", __FUNCTION__, blocktime);
			fdebug("%s(): Block Time = %d", __FUNCTION__, atoi(blocktime));
			g_usleep(atoi(blocktime) * G_USEC_PER_SEC);

			if (atoi(blocktime)) {
				g_timer_destroy(ri->session_timer);
				ri->session_timer = NULL;
			}
		}
	}
  printf("fritzbox_check_login_blocked, result: %i\n",(int)result);
	return result;
}

static inline gchar *make_dots(const gchar *str)
{
	GString *new_str = g_string_new("");
	gunichar chr;
	gchar *next;

	while (str && *str) {
		chr = g_utf8_get_char(str);
		next = g_utf8_next_char(str);

		if (chr > 255) {
			new_str = g_string_append_c(new_str, '.');
		} else {
			new_str = g_string_append_c(new_str, chr);
		}

		str = next;
	}

	return g_string_free(new_str, FALSE);
}

static inline gchar *md5(gchar *input)
{
	GError *error = NULL;
	gchar *ret = NULL;
	gsize written;
	gchar *bin = g_convert(input, -1, "UTF-16LE", "UTF-8", NULL, &written, &error);

	if (error == NULL) {
		ret = g_compute_checksum_for_string(G_CHECKSUM_MD5, (gchar *) bin, written);
		g_free(bin);
	} else {
		fdebug("Error converting utf8 to utf16: '%s'", error->message);
		g_error_free(error);
	}

	return ret;
}


gboolean fritzbox_login_05_50(struct router_icl *ri)
{
  printf("hier fritzbox_login_05_50\n");
	SoupMessage *msg;
	gchar *response = NULL;
	gsize read;
	gchar *challenge = NULL;
	gchar *dots = NULL;
	gchar *str = NULL;
	gchar *md5_str = NULL;
	gchar *url;
	const gchar *data;
	gboolean result;

	if (ri->session_timer && g_timer_elapsed(ri->session_timer, NULL) < 9 * 60) {
		return TRUE;
	} else {
		if (!ri->session_timer) {
			ri->session_timer = g_timer_new();
			g_timer_start(ri->session_timer);
		} else {
			g_timer_reset(ri->session_timer);
		}
	}
  printf("1 fritzbox_login_05_50\n");

	url = g_strdup_printf("http://%s/login_sid.lua", ri->host);
	msg = soup_message_new(SOUP_METHOD_GET, url);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);

		g_timer_destroy(ri->session_timer);
		ri->session_timer = NULL;
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;
  printf("2 fritzbox_login_05_50\n");

	//log_save_data("fritzbox-05_50-login_1.html", data, read);
	g_assert(data != NULL);

	/* <SID>session_id</SID> */
	ri->session_id = xml_extract_tag(data, (gchar*)"SID");

	result = fritzbox_check_login_blocked(data, ri);

	if (!strcmp(ri->session_id, "0000000000000000")) {
//		gchar *user = router_get_login_user(profile);
    gchar *user=g_strdup("");
  printf("27 fritzbox_login_05_50, user: %s\n", user);
//		gchar *password = router_get_login_password(profile);
    /*GSchade*/ gchar* password=g_strdup("bach17raga");
    ///*GSchade*/ password="bach17raga";
  printf("28 fritzbox_login_05_50, password: %s\n", password);

		challenge = xml_extract_tag(data, (gchar*)"Challenge");
		g_object_unref(msg);

		dots = make_dots(password);
		g_free(password);
		str = g_strconcat(challenge, "-", dots, NULL);
		md5_str = md5(str);

		response = g_strconcat(challenge, "-", md5_str, NULL);

		g_free(md5_str);
		g_free(str);
		g_free(dots);
		g_free(challenge);

		url = g_strdup_printf("http://%s/login_sid.lua", ri->host/*router_get_host(profile)*/);
		msg = soup_form_request_new(SOUP_METHOD_POST, url,
		                            "username", user,
		                            "response", response,
		                            NULL);
		g_free(url);

		soup_session_send_message(soup_session, msg);
		g_free(user);
		if (msg->status_code != 200) {
			fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
			g_object_unref(msg);

			g_timer_destroy(ri->session_timer);
			ri->session_timer = NULL;

			return FALSE;
		}
		data = msg->response_body->data;
		read = msg->response_body->length;

  //log_save_data("fritzbox-05_50-login_2.html", data, read);

		g_free(response);

		ri->session_id = xml_extract_tag(data, (gchar*)"SID");

		result = fritzbox_check_login_blocked(data, ri);
	}

	g_object_unref(msg);

  printf("Ende fritzbox_login_05_50\n");
	return result;
}


gboolean fritzbox_login_04_74(struct router_icl *ri)
{
  printf("fritzbox_login_04_74\n");
	SoupMessage *msg;
	gchar *response = NULL;
	gsize read;
	gchar *challenge = NULL;
	gchar *dots = NULL;
	gchar *str = NULL;
	gchar *md5_str = NULL;
	gchar *url;
	const gchar *data;
	gchar *writeaccess;

	if (ri->session_timer && g_timer_elapsed(ri->session_timer, NULL) < 9 * 60) {
		return TRUE;
	} else {
		if (!ri->session_timer) {
			ri->session_timer = g_timer_new();
			g_timer_start(ri->session_timer);
		} else {
			g_timer_reset(ri->session_timer);
		}
	}

	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "getpage", "../html/login_sid.xml",
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200 || !msg->response_body->length) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		fdebug("Message length: %" G_GOFFSET_FORMAT, msg->response_body->length);
		g_object_unref(msg);

		g_timer_destroy(ri->session_timer);
		ri->session_timer = NULL;
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	// log_save_data("fritzbox-04_74-login1.html", data, read);
	g_assert(data != NULL);

	/* <SID>X</SID> */
	ri->session_id = xml_extract_tag(data, (gchar*)"SID");

	/* <iswriteaccess>X</iswriteaccess> */
	writeaccess = xml_extract_tag(data, (gchar*)"iswriteaccess");
	if (writeaccess == NULL) {
		fdebug("writeaccess is NULL");
		g_object_unref(msg);

		g_timer_destroy(ri->session_timer);
		ri->session_timer = NULL;
		return FALSE;
	}

	/* <Challenge>X</Challenge> */
	challenge = xml_extract_tag(data, (gchar*)"Challenge");
	if (challenge == NULL) {
		fdebug("challenge is NULL");
		g_object_unref(msg);

		g_timer_destroy(ri->session_timer);
		ri->session_timer = NULL;
		return FALSE;
	}

	g_object_unref(msg);

	if (atoi(writeaccess) == 0) {
		/* Currently not logged in */
		fdebug("Currently not logged in");

    gchar *password=g_strdup("bach17raga");
		dots = make_dots(password/*router_get_login_password(profile)*/);
		str = g_strconcat(challenge, "-", dots, NULL);
		md5_str = md5(str);

		response = g_strconcat(challenge, "-", md5_str, NULL);

		g_free(md5_str);
		g_free(str);
		g_free(dots);

		url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
		msg = soup_form_request_new(SOUP_METHOD_POST, url,
		                            "login:command/response", response,
		                            "getpage", "../html/login_sid.xml",
		                            NULL);
		g_free(url);

		soup_session_send_message(soup_session, msg);
		if (msg->status_code != 200) {
			fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
			g_object_unref(msg);

			g_timer_destroy(ri->session_timer);
			ri->session_timer = NULL;

			return FALSE;
		}
		data = msg->response_body->data;
		read = msg->response_body->length;

		// log_save_data("fritzbox-04_74-login2.html", data, read);

		g_free(response);

		/* <iswriteaccess>X</iswriteaccess> */
		writeaccess = xml_extract_tag(data, (gchar*)"iswriteaccess");

		/* <Challenge>X</Challenge> */
		challenge = xml_extract_tag(data, (gchar*)"Challenge");

		if ((atoi(writeaccess) == 0) || strcmp(ri->session_id, "0000000000000000")) {
			fdebug("Login failure (%d should be non 0, %s should not be 0000000000000000)", atoi(writeaccess), ri->session_id);

			g_object_unref(msg);

			g_timer_destroy(ri->session_timer);
			ri->session_timer = NULL;

			return FALSE;
		}

		fdebug("Login successful");

		g_free(ri->session_id);
		ri->session_id = xml_extract_tag(data, (gchar*)"SID");

		g_object_unref(msg);
	} else {
		fdebug("Already logged in");
	}

	g_free(challenge);
	g_free(writeaccess);

	return TRUE;
}

gboolean fritzbox_login_04_00(struct router_icl *ri)
{
  printf("fritzbox_login_04_00\n");
	SoupMessage *msg;
	const gchar *data;
	gchar *url;
	gboolean ret = FALSE;
	gsize read;
	gchar *password;

	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);

	//password = router_get_login_password(profile);
	password = g_strdup("bach17raga");
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
				    "login:command/password", password,
				    "var:loginDone", "1",
				    NULL);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		g_warning("Could not load 04_00 login page (Error: %d)", msg->status_code);
		g_object_unref(msg);
		g_free(url);

		return ret;
	}

	data = msg->response_body->data;
	read = msg->response_body->length;

	// log_save_data("fritzbox-04_00-login1.html", data, read);
	g_assert(data != NULL);

	if (!strstr(data, "FRITZ!Box Anmeldung")) {
		ret = TRUE;
	}

	return ret;
}

gboolean fritzbox_login(struct router_icl *ri)
{
  printf("hier fritzbox_login\n");
	if (FIRMWARE_IS(5, 50)) {
		/* Session-ID based on login_sid.lua */
		return fritzbox_login_05_50(ri);
	}

	if (FIRMWARE_IS(4, 74)) {
		/* Session-ID based on login_sid.xml */
		return fritzbox_login_04_74(ri);
	}

	if (FIRMWARE_IS(4, 0)) {
		/* Plain login method */
		return fritzbox_login_04_00(ri);
	}
	return FALSE;
}

struct hrouter {
	const gchar *name;
	gboolean (*present)(struct router_icl *ri);
	gboolean (*login)(struct router_icl *ri);
	gboolean (*logout)(struct router_icl *ri, gboolean force);
	gboolean (*get_settings)(struct router_icl *ri);
	gboolean (*load_journal)(struct router_icl *ri, gchar **data);
	gboolean (*clear_journal)(struct router_icl  *ri);
	gboolean (*dial_number)(struct router_icl *ri, gint port, const gchar *number);
	gboolean (*hangup)(struct router_icl *ri, gint port, const gchar *number);
	gchar *(*load_fax)(struct router_icl *ri, const gchar *filename, gsize *len);
	gchar *(*load_voice)(struct router_icl *ri, const gchar *filename, gsize *len);
	gchar *(*get_ip)(struct router_icl *ri);
	gboolean (*reconnect)(struct router_icl *ri);
	gboolean (*delete_fax)(struct router_icl *ri, const gchar *filename);
	gboolean (*delete_voice)(struct router_icl *ri, const gchar *filename);
};

/** Active router structure */
static struct hrouter *active_router = NULL;
/** Global router plugin list */
static GSList *router_list = NULL;
/** Router login blocked shield */
static gboolean router_login_blocked = FALSE;


/*
gboolean router_present(struct router_icl *ri)
{
  GSList *list;
  fdebug("%s(): called", __FUNCTION__);
  if (!router_list) {
    fdebug("router_present: keine router_list");
    return FALSE;
  }
  unsigned long ru=0;
  for (list = router_list; list != NULL; list = list->next) {
    struct router *router = list->data;
      fdebug("%lu: %s",++ru,router->name);
    if (router->present(ri)) { // !strcmp(router->name,"FRITZ!Box")) {
      active_router = router;
      fdebug("router_present: %s",router->name);
      return TRUE;
    }
      fdebug("not router_present: %s",router->name);
  }

  fdebug("router_present: keiner praesent");
  return FALSE;
}

gboolean router_login(struct profile *profile)
{
	gboolean result;

	if (!active_router) {
		return FALSE;
	}

	if (router_login_blocked) {
		fdebug("%s(): called, but blocked", __FUNCTION__);
		return FALSE;
	}

	result = active_router->login(profile);
	if (!result) {
		g_warning(_("Login data are wrong or permissions are missing.\nPlease check your login data."));
		emit_message(_("Login failed"), _("Login data are wrong or permissions are missing.\nPlease check your login data."));
		router_login_blocked = TRUE;
	}

	return result;
}
*/

gboolean fritzbox_logout(struct router_icl *ri, gboolean force)
{
  printf("fritzbox_logout\n");
	SoupMessage *msg;
	gchar *url;

	if (ri->session_timer && !force) {
		return TRUE;
	}

	//url = g_strdup_printf("http://%s/cgi-bin/webcm", router_get_host(profile));
	//msg = soup_form_request_new(SOUP_METHOD_POST, url,
	//                            "sid", profile->router_info->session_id,
	//                            "security:command/logout", "",
	//                            "getpage", "../html/confirm_logout.html",
	//                            NULL);
	url = g_strdup_printf("http://%s/home/home.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "sid", ri->session_id,
	                            "logout", "1",
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}

	if (ri->session_timer != NULL) {
		g_timer_destroy(ri->session_timer);
		ri->session_timer = NULL;
	}

	g_object_unref(msg);
	fdebug("%s(): Successful", __FUNCTION__);

	return TRUE;
}

gchar *call_canonize_number(struct router_icl *ri, const gchar *number)
{
	GString *new_number;

	new_number = g_string_sized_new(strlen(number));
	while (*number) {
		if (isdigit(*number) || *number == '*' || *number == '#') {
			g_string_append_c(new_number, *number);
		} else if (*number == '+') {
			g_string_append(new_number, ri->lkz_prefix);
		}
		number++;
	}
	return g_string_free(new_number, FALSE);
}

gchar *call_format_number(struct router_icl *ri, const gchar *number, enum number_format output_format)
{
	gchar *tmp;
	gchar *canonized;
	gchar *my_area_code;
	gint number_format = NUMBER_FORMAT_UNKNOWN;
	const gchar *my_prefix;
	gchar *result = NULL;

	/* Check for internal sip numbers first */
	if (strchr(number, '@')) {
		return g_strdup(number);
	}

	canonized = tmp = call_canonize_number(ri,number);


	/* we only need to check for international prefix, as call_canonize_number() already replaced '+'
	 * Example of the following:
	 *    tmp = 00494012345678  with international_prefix 00 and my_country_code 49
	 *    number_format = NUMBER_FORMAT_UNKNOWN
	 */
	if (!strncmp(tmp, ri->lkz_prefix, strlen(ri->lkz_prefix))) {
		/* International format number */
		tmp += strlen(ri->lkz_prefix);
		number_format = NUMBER_FORMAT_INTERNATIONAL;

		/* Example:
		 * tmp = 494012345678
		 * number_format = NUMBER_FORMAT_INTERNATIONAL
		 */
		if (!strncmp(tmp, ri->lkz, strlen(ri->lkz)))  {
			/* national number */
			tmp = tmp + strlen(ri->lkz);
			number_format = NUMBER_FORMAT_NATIONAL;

			/* Example:
			 * tmp = 4012345678
			 * number_format = NUMBER_FORMAT_NATIONAL
			 */
		}
	} else {
		/* not an international format, test for national or local format */
		if (!EMPTY_STRING(ri->okz_prefix) && !strncmp(tmp, ri->okz_prefix, strlen(ri->okz_prefix))) {
			tmp = tmp + strlen(ri->okz_prefix);
			number_format = NUMBER_FORMAT_NATIONAL;

			/* Example:
			 * Input was: 04012345678
			 * tmp = 4012345678
			 * number_format = NUMBER_FORMAT_NATIONAL
			 */
		} else {
			number_format = NUMBER_FORMAT_LOCAL;
			/* Example:
			 * Input was 12345678
			 * tmp = 12345678
			 * number_format = NUMBER_FORMAT_LOCAL
			 */
		}
	}

	if ((number_format == NUMBER_FORMAT_NATIONAL) && (!strncmp(tmp, ri->okz, strlen(ri->okz)))) {
		/* local number */
		tmp = tmp + strlen(ri->okz);
		number_format = NUMBER_FORMAT_LOCAL;

		/* Example:
		 * Input was 4012345678
		 * tmp = 12345678
		 * number_format = NUMBER_FORMAT_LOCAL
		 */
	}

	switch (output_format) {
	case NUMBER_FORMAT_LOCAL:
	/* local number format */
	case NUMBER_FORMAT_NATIONAL:
		/* national number format */
		switch (number_format) {
		case NUMBER_FORMAT_LOCAL:
			if (output_format == NUMBER_FORMAT_LOCAL) {
				result = g_strdup(tmp);
			} else {
				result = g_strconcat(ri->okz_prefix, ri->okz, tmp, NULL);
			}
			break;
		case NUMBER_FORMAT_NATIONAL:
			result = g_strconcat(ri->okz_prefix, tmp, NULL);
			break;
		case NUMBER_FORMAT_INTERNATIONAL:
			result = g_strconcat(ri->lkz_prefix, tmp, NULL);
			break;
		}
		break;
	case NUMBER_FORMAT_INTERNATIONAL:
	/* international prefix + international format */
	case NUMBER_FORMAT_INTERNATIONAL_PLUS:
		/* international format prefixed by a + */
		my_prefix = (output_format == NUMBER_FORMAT_INTERNATIONAL_PLUS) ? "+" : ri->lkz_prefix;
		switch (number_format) {
		case NUMBER_FORMAT_LOCAL:
			result = g_strconcat(my_prefix, ri->lkz, ri->okz, tmp, NULL);
			break;
		case NUMBER_FORMAT_NATIONAL:
			result = g_strconcat(my_prefix, ri->lkz, tmp, NULL);
			break;
		case NUMBER_FORMAT_INTERNATIONAL:
			result = g_strconcat(my_prefix, tmp, NULL);
			break;
		}
		break;
	default:
		g_assert(output_format);
		break;
	}


	g_free(canonized);
	g_assert(result != NULL);

	return result;
}

gchar *call_scramble_number(const gchar *number)
{
	gchar *scramble;
	gint len;

	len = strlen(number);
	scramble = g_strdup(number);

	if (len > 2) {
		gint index;
		gint end = len;

		if (len > 4) {
			end = len - 1;
		}

		for (index = 2; index < end; index++) {
			scramble[index] = 'X';
		}
	}

	return scramble;
}

/** phone port names */
struct phone_port fritzbox_phone_ports[PORT_MAX] = {
	/* Analog */
	{(gchar*)"telcfg:settings/MSN/Port0/Name", PORT_ANALOG1, 1},
	{(gchar*)"telcfg:settings/MSN/Port1/Name", PORT_ANALOG2, 2},
	{(gchar*)"telcfg:settings/MSN/Port2/Name", PORT_ANALOG3, 3},
	/* ISDN */
	{(gchar*)"telcfg:settings/NTHotDialList/Name1", PORT_ISDN1, 51},
	{(gchar*)"telcfg:settings/NTHotDialList/Name2", PORT_ISDN2, 52},
	{(gchar*)"telcfg:settings/NTHotDialList/Name3", PORT_ISDN3, 53},
	{(gchar*)"telcfg:settings/NTHotDialList/Name4", PORT_ISDN4, 54},
	{(gchar*)"telcfg:settings/NTHotDialList/Name5", PORT_ISDN5, 55},
	{(gchar*)"telcfg:settings/NTHotDialList/Name6", PORT_ISDN6, 56},
	{(gchar*)"telcfg:settings/NTHotDialList/Name7", PORT_ISDN7, 57},
	{(gchar*)"telcfg:settings/NTHotDialList/Name8", PORT_ISDN8, 58},
	/* DECT */
	{(gchar*)"telcfg:settings/Foncontrol/User1/Name", PORT_DECT1, 60},
	{(gchar*)"telcfg:settings/Foncontrol/User2/Name", PORT_DECT2, 61},
	{(gchar*)"telcfg:settings/Foncontrol/User3/Name", PORT_DECT3, 62},
	{(gchar*)"telcfg:settings/Foncontrol/User4/Name", PORT_DECT4, 63},
	{(gchar*)"telcfg:settings/Foncontrol/User5/Name", PORT_DECT5, 64},
	{(gchar*)"telcfg:settings/Foncontrol/User6/Name", PORT_DECT6, 65},
	/* IP-Phone */
	{(gchar*)"telcfg:settings/VoipExtension0/Name", PORT_IP1, 620},
	{(gchar*)"telcfg:settings/VoipExtension1/Name", PORT_IP2, 621},
	{(gchar*)"telcfg:settings/VoipExtension2/Name", PORT_IP3, 622},
	{(gchar*)"telcfg:settings/VoipExtension3/Name", PORT_IP4, 623},
	{(gchar*)"telcfg:settings/VoipExtension4/Name", PORT_IP5, 624},
	{(gchar*)"telcfg:settings/VoipExtension5/Name", PORT_IP6, 625},
	{(gchar*)"telcfg:settings/VoipExtension6/Name", PORT_IP7, 626},
	{(gchar*)"telcfg:settings/VoipExtension7/Name", PORT_IP8, 627},
	{(gchar*)"telcfg:settings/VoipExtension8/Name", PORT_IP9, 628},
	{(gchar*)"telcfg:settings/VoipExtension9/Name", PORT_IP10, 629},
};

gint fritzbox_find_phone_port(gint dial_port)
{
	gint index;

	for (index = 0; index < PORT_MAX; index++) {
		if (fritzbox_phone_ports[index].number == dial_port) {
			return fritzbox_phone_ports[index].type;
		}
	}

	return -1;
}

void lese(JsonReader *reader,const char *name,const gchar** ziel,const char *altname)
{
	json_reader_read_member(reader, name);
	*ziel = json_reader_get_string_value(reader);
	fdebug("%14s: %s",name, *ziel);
	//g_settings_set_string(ri->settings, altname, lkz);
	json_reader_end_member(reader);
}

gboolean fritzbox_get_settings_query(struct router_icl *ri)
{
	JsonParser *parser;
	JsonReader *reader;
	SoupMessage *msg;
	const gchar *data;
	gsize read;
	gchar *url;
	gchar *scramble;
	gint i;

//  printf("?!?!%s\n",geturl("http://fritz.box:49000/tr64desc.xml"));
  gchar* dat=(gchar*)geturl("http://fritz.box:49000/tr64desc.xml");
  gchar *fbname=xml_extract_tag(dat, (gchar*)"friendlyName");
  printf("friendlyName: %s\n",fbname);

	fdebug("Get settings");

	/* Login */
	if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	g_test_timer_start();

	/* Extract data */
	url = g_strdup_printf("http://%s/query.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
								"LKZPrefix", "telcfg:settings/Location/LKZPrefix",
								"LKZ", "telcfg:settings/Location/LKZ",
								"OKZPrefix", "telcfg:settings/Location/OKZPrefix",
								"OKZ", "telcfg:settings/Location/OKZ",
								"Port0", "telcfg:settings/MSN/Port0/Name",
								"Port1", "telcfg:settings/MSN/Port1/Name",
								"Port2", "telcfg:settings/MSN/Port2/Name",
								"TAM", "tam:settings/TAM/list(Name)",
								"ISDNName0", "telcfg:settings/NTHotDialList/Name0",
								"ISDNName1", "telcfg:settings/NTHotDialList/Name1",
								"ISDNName2", "telcfg:settings/NTHotDialList/Name2",
								"ISDNName3", "telcfg:settings/NTHotDialList/Name3",
								"ISDNName4", "telcfg:settings/NTHotDialList/Name4",
								"ISDNName5", "telcfg:settings/NTHotDialList/Name5",
								"ISDNName6", "telcfg:settings/NTHotDialList/Name6",
								"ISDNName7", "telcfg:settings/NTHotDialList/Name7",
								"DECT", "telcfg:settings/Foncontrol/User/list(Name,Type,Intern)",
								"MSN", "telcfg:settings/SIP/list(MSN,Name)",
								"FaxMailActive", "telcfg:settings/FaxMailActive",
								"storage", "ctlusb:settings/storage-part0",
								"FaxMSN0", "telcfg:settings/FaxMSN0",
								"FaxKennung", "telcfg:settings/FaxKennung",
								"DialPort", "telcfg:settings/DialPort",
								"TamStick", "tam:settings/UseStick",
								"FaxSavePath", "telcfg:settings/FaxSavePath",
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);

		fritzbox_logout(ri, FALSE);
		return FALSE;
	}
	data = msg->response_body->data;
  printf("0!!!!!!!!!!!!!!!!!!!!!!!!!!!!! data: %s\n",(gchar*)data);
	read = msg->response_body->length;

	//log_save_data("fritzbox-06_35-query.html", data, read);
	g_assert(data != NULL);

	parser = json_parser_new();
	json_parser_load_from_data(parser, data, read, NULL);

	reader = json_reader_new(json_parser_get_root(parser));

  lese(reader,"LKZ",&ri->lkz,"country-code");
  lese(reader,"LKZPrefix",&ri->lkz_prefix,"international-call-prefix");
  lese(reader,"OKZ",&ri->okz,"area-code");
  lese(reader,"OKZPrefix",&ri->okz_prefix,"national-call-prefix");
  lese(reader,"FaxMailActive",&ri->port_str,"");
	ri->port = atoi(ri->port_str);
  lese(reader,"FaxKennung",&ri->fax_ident,"fax-header");
	//scramble = call_scramble_number(ri->fax_ident);
	//fdebug("FaxKennung: %s", scramble);
	//g_free(scramble);

	if ((ri->port == 2 || ri->port == 3)) {
    lese(reader,"Fax Storage",&ri->storage,"fax-volume");
	} else {
    ri->storage="";
	}

  lese(reader,"FaxMSN0",&ri->fax_msn,"fax-number");
	ri->formated_number = call_format_number(ri, ri->fax_msn, NUMBER_FORMAT_INTERNATIONAL_PLUS);

	/* Parse phones */
	fdebug("POTS");
	for (i = 0; i < 3; i++) {
		gchar name_in[11];
		gchar name_analog[13];

		memset(name_in, 0, sizeof(name_in));
		g_snprintf(name_in, sizeof(name_in), "Port%d", i);
    lese(reader,name_in,&ri->pname[i],"");

		memset(name_analog, 0, sizeof(name_analog));
		g_snprintf(name_analog, sizeof(name_analog), "name-analog%d", i + 1);
    lese(reader,name_analog,&ri->name_analog[i],"");
	}

	fdebug("ISDN");
	for (i = 0; i < 8; i++) {
		gchar name_in[11];
		gchar name_isdn[13];

		memset(name_in, 0, sizeof(name_in));
		g_snprintf(name_in, sizeof(name_in), "ISDNName%d", i+1);
    lese(reader,name_in,&ri->iname[i],"");

		memset(name_isdn, 0, sizeof(name_isdn));
		g_snprintf(name_isdn, sizeof(name_isdn), "name-isdn%d", i + 1);
    lese(reader,name_isdn,&ri->name_isdn[i],"");
	}

	fdebug("DECTs:");
	json_reader_read_member(reader, "DECT");
	gint count = json_reader_count_elements(reader);

	for (i = 1; i < count; i++) {
		const gchar *tmp;
		const gchar *intern;
		gchar name_dect[11];

		json_reader_read_element(reader, i);
    lese(reader,"Name",&ri->dname[i],"");
		memset(name_dect, 0, sizeof(name_dect));
		g_snprintf(name_dect, sizeof(name_dect), "name-dect%d", i);
    lese(reader,name_dect,&ri->intern[i],"");

		json_reader_end_element(reader);
	}

	json_reader_end_member(reader);

	/* Parse msns */
	fdebug("MSNs:");
	json_reader_read_member(reader, "MSN");
	count = json_reader_count_elements(reader);

	ri->numbers = NULL;
	ri->nname = NULL;
	gint phones = 0;

	for (i = 0; i < count; i++) {
		const gchar *tmp;

		json_reader_read_element(reader, i);
		json_reader_read_member(reader, "MSN");
		tmp = json_reader_get_string_value(reader);
		json_reader_end_member(reader);

		if (!EMPTY_STRING(tmp)) {
			phones++;
			ri->numbers = (gchar**)g_realloc(ri->numbers, (phones + 1) * sizeof(char*));
			ri->numbers[phones - 1] = g_strdup(tmp);
			ri->numbers[phones] = NULL;

			json_reader_read_member(reader, "Name");
			tmp = json_reader_get_string_value(reader);
			ri->nname = (gchar**)g_realloc(ri->nname, (phones + 1) * sizeof(char*));
			ri->nname[phones - 1] = g_strdup(tmp);
			ri->nname[phones] = NULL;

			json_reader_end_member(reader);
		}

		json_reader_end_element(reader);
	}
//	g_settings_set_strv(ri->settings, "numbers", (const gchar * const *)numbers);
  for(i=0;ri->numbers[i];i++) {
    fdebug(" MSN: %s",ri->numbers[i]);
    fdebug(" Name: %s",ri->nname[i]);
  }

	json_reader_end_member(reader);
  /*
	json_reader_read_member(reader, name);
	*ziel = json_reader_get_string_value(reader);
	fdebug("%14s: %s",name, *ziel);
	//g_settings_set_string(ri->settings, altname, lkz);
	json_reader_end_member(reader);
*/

  lese(reader,"DialPort",&ri->dialport,"");
	ri->port = atoi(ri->dialport);
  ri->phone_port=fritzbox_find_phone_port(ri->port);
	fdebug("    phone_port: %d", ri->phone_port);
  
  lese(reader,"TamStick",&ri->tamstickstr,"");
	if (ri->tamstickstr && atoi(&ri->tamstickstr[0])) {
    ri->tamstick=atoi(ri->tamstickstr);
	} else {
    ri->tamstick=0;
	}

	g_object_unref(reader);
	g_object_unref(parser);

	g_object_unref(msg);
	fdebug("Result: %f", g_test_timer_elapsed());

	/* The end - exit */
	fritzbox_logout(ri, FALSE);

 	return TRUE;
}

/** Mapping between config value and port type */
struct phone_port router_phone_ports[PORT_MAX] = {
	{(gchar*)"name-analog1", PORT_ANALOG1, -1},
	{(gchar*)"name-analog2", PORT_ANALOG2, -1},
	{(gchar*)"name-analog3", PORT_ANALOG3, -1},
	{(gchar*)"name-isdn1", PORT_ISDN1, -1},
	{(gchar*)"name-isdn2", PORT_ISDN2, -1},
	{(gchar*)"name-isdn3", PORT_ISDN3, -1},
	{(gchar*)"name-isdn4", PORT_ISDN4, -1},
	{(gchar*)"name-isdn5", PORT_ISDN5, -1},
	{(gchar*)"name-isdn6", PORT_ISDN6, -1},
	{(gchar*)"name-isdn7", PORT_ISDN7, -1},
	{(gchar*)"name-isdn8", PORT_ISDN8, -1},
	{(gchar*)"name-dect1", PORT_DECT1, -1},
	{(gchar*)"name-dect2", PORT_DECT2, -1},
	{(gchar*)"name-dect3", PORT_DECT3, -1},
	{(gchar*)"name-dect4", PORT_DECT4, -1},
	{(gchar*)"name-dect5", PORT_DECT5, -1},
	{(gchar*)"name-dect6", PORT_DECT6, -1},
	{(gchar*)"name-sip0", PORT_IP1, -1},
	{(gchar*)"name-sip1", PORT_IP2, -1},
	{(gchar*)"name-sip2", PORT_IP3, -1},
	{(gchar*)"name-sip3", PORT_IP4, -1},
	{(gchar*)"name-sip4", PORT_IP5, -1},
	{(gchar*)"name-sip5", PORT_IP6, -1},
	{(gchar*)"name-sip6", PORT_IP7, -1},
	{(gchar*)"name-sip7", PORT_IP8, -1},
	{(gchar*)"name-sip8", PORT_IP9, -1},
	{(gchar*)"name-sip9", PORT_IP10, -1}
};

void fritzbox_extract_phone_names_06_35(struct router_icl *ri, const gchar *data, gsize read)
{
	gchar *regex_str = g_strdup_printf("<option(\\w|\\s)+value=\"(?P<port>\\d{1,3})\">(?P<name>(\\w|\\s|-)+)</option>");
	GRegex *regex = NULL;
	GError *error = NULL;
	GMatchInfo *match_info;

	regex = g_regex_new(regex_str, (GRegexCompileFlags)0, (GRegexMatchFlags)0, &error);
	g_assert(regex != NULL);

	g_regex_match(regex, data, (GRegexMatchFlags)0, &match_info);

	while (match_info && g_match_info_matches(match_info)) {
		gchar *port = g_match_info_fetch_named(match_info, "port");
		gchar *name = g_match_info_fetch_named(match_info, "name");

		if (port && name) {
			gint val = atoi(port);
			gint index;

			for (index = 0; index < PORT_MAX; index++) {
				if (fritzbox_phone_ports[index].number == val) {
					fdebug("Port %d: '%s'", index, name);
//					g_settings_set_string(ri->settings, router_phone_ports[index].name, name);
          ri->pname[index]=name;
				}
			}
		}

		if (g_match_info_next(match_info, NULL) == FALSE) {
			break;
		}
	}

	g_match_info_free(match_info);
	g_free(regex_str);
}

/**
 * \brief Extract XML Tags: <TAG>VALUE</TAG>
 * \param data data to parse
 * \param tag tag to extract
 * \return tag values
 */
gchar **xml_extract_tags(const gchar *data, gchar *tag_start, gchar *tag_end)
{
	gchar *regex_str = g_strdup_printf("<%s>[^<]*</%s>", tag_start, tag_end);
	GRegex *regex = NULL;
	GError *error = NULL;
	GMatchInfo *match_info;
	gchar **entries = NULL;
	gint index = 0;

	regex = g_regex_new(regex_str, (GRegexCompileFlags)0, (GRegexMatchFlags)0, &error);
	g_assert(regex != NULL);

	g_regex_match(regex, data, (GRegexMatchFlags)0, &match_info);

	while (match_info && g_match_info_matches(match_info)) {
		gint start;
		gint end;
		gboolean fetched = g_match_info_fetch_pos(match_info, 0, &start, &end);

		if (fetched == TRUE) {
			gchar *tag_start_pos = (gchar*)strchr(data + start, '>');
			gchar *tag_end_pos = (gchar*)strchr(tag_start_pos + 1, '<');
			gint entry_size = tag_end_pos - tag_start_pos - 1;

			entries = (gchar**)g_realloc(entries, (index + 2) * sizeof(gchar *));
			entries[index] = (gchar*)g_malloc0(entry_size + 1);
			strncpy(entries[index], tag_start_pos + 1, entry_size);
			entries[index + 1] = NULL;
			index++;
		}

		if (g_match_info_next(match_info, NULL) == FALSE) {
			break;
		}
	}

	g_match_info_free(match_info);
	g_free(regex_str);

	return entries;
}

/**
 * \brief Checks if @strv contains @str. @strv must not be %NULL.
 * \strv a %NULL-terminated array of strings
 * \str a string
 * \return %TRUE if @str is an element of @strv, according to g_str_equal().
 */
gboolean strv_contains(const gchar *const *strv, const gchar *str)
{
	g_return_val_if_fail(strv != NULL, FALSE);
	g_return_val_if_fail(str != NULL, FALSE);

	for (; *strv != NULL; strv++) {
		if (g_str_equal(str, *strv)) {
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * \brief Remove duplicate entries from string array
 * \param numbers input string array
 * \return duplicate free string array
 */
gchar **strv_remove_duplicates(gchar **numbers)
{
	gchar **ret = NULL;
	gint len = g_strv_length(numbers);
	gint idx;
	gint ret_idx = 1;

	for (idx = 0; idx < len; idx++) {
		if (!ret || !strv_contains((const gchar * const *)ret, numbers[idx])) {
			ret = (gchar**)g_realloc(ret, (ret_idx + 1) * sizeof(char *));
			ret[ret_idx - 1] = g_strdup(numbers[idx]);
			ret[ret_idx] = NULL;

			ret_idx++;
		}
	}

	return ret;
}

/**
 * \brief Extract phone numbers from webpage data
 * \param profile profile structure
 * \param data webpage data
 */
static void fritzbox_detect_controller_06_35(struct router_icl *ri, const gchar *data)
{
	gint index;
	gint type = 4;

	for (index = 0; index < PORT_MAX; index++) {
		if (!EMPTY_STRING(router_phone_ports[index].name)) {
			if (index < PORT_ISDNALL) {
				/* Analog */
				type = 3;
			} else if (index < PORT_IP1) {
				/* ISDN */
				type = 0;
			} else {
				/* SIP */
				type = 4;
			}
		}
	}

	fdebug("Setting controllers to %d", type);
	//g_settings_set_int(ri->settings, "fax-controller", type);
	//g_settings_set_int(ri->settings, "phone-controller", type);
  ri->faxcontroller=type;
  ri->phonecontroller=type;
}

gchar *xml_extract_tag_value(gchar *data, gchar *tag)
{
	gchar *pos = g_strstr_len(data, -1, tag);
	gchar *value;
	gchar *end;
	gchar *ret = NULL;
	gsize len;

	if (!pos) {
		return ret;
	}

	value = g_strstr_len(pos, -1, "value=\"");
	if (!value) {
		return ret;
	}

	value += 7;

	end = g_strstr_len(value, -1, "\"");
	if (!end) {
		return ret;
	}

	len = end - value;
	if (len > 0) {
		ret = (gchar*)g_malloc0(len);
		memcpy(ret, value, len);
	}

	return ret;
}


gboolean fritzbox_get_fax_information_06_35(struct router_icl *ri)
{
	SoupMessage *msg;
	const gchar *data;
	gsize read;
	gchar *url;

	url = g_strdup_printf("http://%s/fon_devices/fax_option.lua", ri->host/*router_get_host(ri)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-06_35-get-settings-fax-option.html", data, read);

	g_assert(data != NULL);

	/* name="headline" value="...name..." > */
	gchar *regex_str = g_strdup_printf("<input.+name=\"headline\" value=\"(?P<name>(\\w|\\s|-)+)\" >");
	GRegex *regex = NULL;
	GError *error = NULL;
	GMatchInfo *match_info;

	regex = g_regex_new(regex_str, (GRegexCompileFlags)0, (GRegexMatchFlags)0, &error);
	g_assert(regex != NULL);

	g_regex_match(regex, data, (GRegexMatchFlags)0, &match_info);

	while (match_info && g_match_info_matches(match_info)) {
		gchar *name = g_match_info_fetch_named(match_info, "name");

		if (name) {
			gchar *scramble = call_scramble_number(name);
			fdebug("Fax-Header: '%s'", scramble);
			g_free(scramble);
			//g_settings_set_string(ri->settings, "fax-header", name);
      ri->faxheaders=name;
			break;
		}

		if (g_match_info_next(match_info, NULL) == FALSE) {
			break;
		}
	}

	g_match_info_free(match_info);
	g_free(regex_str);

	/* input type="checkbox" id="uiFaxSaveUsb" name="fax_save_usb"  checked  disabled> */
	regex_str = g_strdup_printf("<input type=\"checkbox\" id=\"uiFaxSaveUsb\" name=\"fax_save_usb\"(?P<checked>(\\w|\\s)+)disabled>");
	error = NULL;
	gboolean store = FALSE;

	regex = g_regex_new(regex_str, (GRegexCompileFlags)0, (GRegexMatchFlags)0, &error);
	g_assert(regex != NULL);

	g_regex_match(regex, data, (GRegexMatchFlags)0, &match_info);

	while (match_info && g_match_info_matches(match_info)) {
		gchar *checked = g_match_info_fetch_named(match_info, "checked");

		if (checked && strstr(checked, "checked")) {
			store = TRUE;
			break;
		}

		if (g_match_info_next(match_info, NULL) == FALSE) {
			break;
		}
	}

	g_match_info_free(match_info);
	g_free(regex_str);

  ri->tamstick=store;
	//g_settings_set_int(ri->settings, "tam-stick", store);
  ri->faxvolume=(gchar*)"";
	//g_settings_set_string(ri->settings, "fax-volume", "");

	g_object_unref(msg);

	if (store) {
		url = g_strdup_printf("http://%s/storage/settings.lua", ri->host/*router_get_host(ri)*/);
		msg = soup_form_request_new(SOUP_METHOD_GET, url,
		                            "sid", ri->session_id,
		                            NULL);
		g_free(url);

		soup_session_send_message(soup_session, msg);
		if (msg->status_code != 200) {
			fdebug("Received status code: %d", msg->status_code);
			g_object_unref(msg);
			return FALSE;
		}
		data = msg->response_body->data;
		read = msg->response_body->length;

		//log_save_data("fritzbox-06_35-get-settings-fax-usb.html", data, read);

		/* <td id="/var/media/ftp/PatriotMemory-01"> */

		regex_str = g_strdup_printf("<td id=\"/var/media/ftp/(?P<volume>(\\w|\\s|\\d|-)+)\"");
		error = NULL;

		regex = g_regex_new(regex_str, (GRegexCompileFlags)0, (GRegexMatchFlags)0, &error);
		g_assert(regex != NULL);

		g_regex_match(regex, data, (GRegexMatchFlags)0, &match_info);

		while (match_info && g_match_info_matches(match_info)) {
			gchar *volume = g_match_info_fetch_named(match_info, "volume");

			if (volume) {
				fdebug("Fax-Storage-Volume: '%s'", volume);
				//g_settings_set_string(ri->settings, "fax-volume", volume);
        ri->faxvolume=volume;
        break;
			}

			if (g_match_info_next(match_info, NULL) == FALSE) {
				break;
			}
		}

		g_match_info_free(match_info);
		g_free(regex_str);

		g_object_unref(msg);
	}

	url = g_strdup_printf("http://%s/fon_devices/fax_send.lua", ri->host/*router_get_host(ri)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-06_35-get-settings-fax-send.html", data, read);

	g_assert(data != NULL);

	/* <option value="num">num */
	regex_str = g_strdup_printf("<option value=\"(?P<msn>\\d+)\">");
	error = NULL;

	regex = g_regex_new(regex_str, (GRegexCompileFlags)0, (GRegexMatchFlags)0, &error);
	g_assert(regex != NULL);

	g_regex_match(regex, data, (GRegexMatchFlags)0, &match_info);

	while (match_info && g_match_info_matches(match_info)) {
		gchar *msn = g_match_info_fetch_named(match_info, "msn");

		if (msn) {
			gchar *formated_number;
			gchar *scramble;

			formated_number = call_format_number(ri, msn, NUMBER_FORMAT_INTERNATIONAL_PLUS);

			scramble = call_scramble_number(msn);
			fdebug("Fax number: '%s'", scramble);
			g_free(scramble);

			//g_settings_set_string(ri->settings, "fax-number", msn);
      ri->fax_msn=msn;

			//g_settings_set_string(ri->settings, "fax-ident", formated_number);
      ri->formated_number=formated_number;
			g_free(formated_number);
			break;
		}

		if (g_match_info_next(match_info, NULL) == FALSE) {
			break;
		}
	}

	g_match_info_free(match_info);
	g_free(regex_str);

	g_object_unref(msg);

	return TRUE;
}

/**
 * \brief Extract XML input tag reverse: name="TAG" ... value="VALUE"
 * \param data data to parse
 * \param tag tag to extract
 * \return tag value
 */
gchar *xml_extract_input_value_r(const gchar *data, gchar *tag)
{
	gchar *name = g_strdup_printf("name=\"%s\"", tag);
	gchar *start = g_strstr_len(data, -1, name);
	gchar *val_start = NULL;
	gchar *val_end = NULL;
	gchar *value = NULL;
	gssize val_size;

	g_free(name);
	if (start == NULL) {
		return NULL;
	}

	val_start = g_strrstr_len(data, start - data, "value=\"");
	g_assert(val_start != NULL);

	val_start += 7;

	val_end = g_strstr_len(val_start, -1, "\"");

	val_size = val_end - val_start;
	g_assert(val_size >= 0);

	value = (gchar*)g_malloc0(val_size + 1);
	memcpy(value, val_start, val_size);

	return value;
}


/**
 * \brief Get settings via lua-scripts (phone numbers/names, default controller, tam setting, fax volume/settings, prefixes, default dial port)
 * \param profile profile information structure
 * \return error code
 */
gboolean fritzbox_get_settings_06_35(struct router_icl *ri)
{
	SoupMessage *msg;
	const gchar *data;
	gsize read;
	gchar *url;

	fdebug("Get settings");

	/* Login */
	if (!fritzbox_login(ri)) {
		return FALSE;
	}

	g_test_timer_start();
	/* Extract phone numbers */
	url = g_strdup_printf("http://%s/fon_num/fon_num_list.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
  printf("1!!!!!!!!!!!!!!!!!!!!!!!!!!!!! data: %s\n",(gchar*)data);
	read = msg->response_body->length;

	//log_save_data("fritzbox-06_35-get-settings-0.html", data, read);
	g_assert(data != NULL);

	gchar **numbers = xml_extract_tags(data, (gchar*)"td title=\"[^\"]*\"", (gchar*)"td");

	if (g_strv_length(ri->numbers)) {
		ri->/*gchar **profile_*/numbers = strv_remove_duplicates(numbers);
		gint idx;

		if (g_strv_length(ri->/*profile_*/numbers)) {
			for (idx = 0; idx < g_strv_length(ri->/*profile_*/numbers); idx++) {
				fdebug("Adding MSN '%s'", ri->numbers[idx]);
			}
			//g_settings_set_strv(ri->settings, "numbers", (const gchar * const *)profile_numbers);
		}
		g_strfreev(numbers);

	}
	g_object_unref(msg);

	/* Extract phone names, default controller */
	url = g_strdup_printf("http://%s/fon_num/dial_foncalls.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-06_35-get-settings-1.html", data, read);
	g_assert(data != NULL);

	fritzbox_extract_phone_names_06_35(ri, data, read);

	/* Try to detect controller */
	fritzbox_detect_controller_06_35(ri, data);

	gchar *dialport = xml_extract_tag_value((gchar*)data, (gchar*)"option selected");
	if (dialport) {
		gint port = atoi(dialport);
		gint phone_port = fritzbox_find_phone_port(port);
		fdebug("Dial port: %s, phone_port: %d", dialport, phone_port);
    ri->port=phone_port;
  }
	g_free(dialport);

	g_object_unref(msg);

	/* Extract city/country/area prefix */
	url = g_strdup_printf("http://%s/fon_num/sip_option.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-06_35-get-settings-2.html", data, read);
	g_assert(data != NULL);

	gchar *value;

	value = xml_extract_input_value_r(data, (gchar*)"lkz");
	if (value != NULL && strlen(value) > 0) {
		fdebug("lkz: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "country-code", value);
  ri->lkz=value;
	g_free(value);

	value = xml_extract_input_value_r(data, (gchar*)"lkz_prefix");
	if (value != NULL && strlen(value) > 0) {
		fdebug("lkz prefix: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "international-call-prefix", value);
  ri->lkz_prefix=value;
	g_free(value);

	value = xml_extract_input_value_r(data, (gchar*)"okz");
	if (value != NULL && strlen(value) > 0) {
		fdebug("okz: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "area-code", value);
  ri->okz=value;
	g_free(value);

	value = xml_extract_input_value_r(data, (gchar*)"okz_prefix");
	if (value != NULL && strlen(value) > 0) {
		fdebug("okz prefix: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "national-call-prefix", value);
  ri->okz_prefix=value;
	g_free(value);

	g_object_unref(msg);
	fdebug("Result: %f", g_test_timer_elapsed());

	/* Extract Fax information */
	fritzbox_get_fax_information_06_35(ri);

	/* The end - exit */
	fritzbox_logout(ri, FALSE);

	return TRUE;
}

/**
 * \brief Extract XML list tag: ["TAG"] = "VALUE"
 * \param data data to parse
 * \param tag tag to extract
 * \return tag value
 */
gchar *xml_extract_list_value(const gchar *data, gchar *tag)
{
	gchar *name = g_strdup_printf("\"%s\"", tag);
	gchar *start = g_strstr_len(data, -1, name);
	gchar *val_start = NULL;
	gchar *val_end = NULL;
	gchar *value = NULL;
	gssize val_size;

	g_free(name);
	if (start == NULL) {
		return NULL;
	}

	start += strlen(tag) + 2;

	val_start = g_strstr_len(start, -1, "\"");
	g_assert(val_start != NULL);

	val_start += 1;

	val_end = g_strstr_len(val_start, -1, "\"");

	val_size = val_end - val_start;
	g_assert(val_size >= 0);

	value = (gchar*)g_malloc0(val_size + 1);
	memcpy(value, val_start, val_size);

	return value;
}

/**
 * \brief Number compare function
 * \param a string a
 * \param b string b
 * \return return value of strcmp
 */
gint number_compare(gconstpointer a, gconstpointer b)
{
	return strcmp((char*)a, (char*)b);
}


/**
 * \brief Extract number from fw 05.50
 * \param number_list pointer to number list
 * \param data incoming page data
 * \param msn_str msn string to lookup
 * \return TRUE on success, otherwise FALSE
 */
gboolean extract_number_05_50(GSList **number_list, const gchar *data, gchar *msn_str)
{
	gchar *fon;

	fon = xml_extract_list_value(data, msn_str);
	if (!EMPTY_STRING(fon) && isdigit(fon[0])) {
		if (!g_slist_find_custom(*number_list, fon, number_compare)) {
			if (strlen(fon) > 2) {
				*number_list = g_slist_prepend(*number_list, fon);
			}
		} else {
			g_free(fon);
		}

		return TRUE;
	}

	g_free(fon);
	return FALSE;
}


/**
 * \brief Extract phone numbers from webpage data
 * \param profile profile structure
 * \param data webpage data
 */
static void fritzbox_detect_controller_05_50(struct router_icl *ri, const gchar *data)
{
	gint index;
	gint type = -1;
	gint port;
	GSList *number_list = NULL;

	/* POTS first! */
	if (extract_number_05_50(&number_list, data, (gchar*)"telcfg:settings/MSN/POTS")) {
		type = 3;
		goto set;
	}

	/* PortX-MSN */
	for (port = 0; port < 3; port++) {
		for (index = 0; index < 10; index++) {
			gchar *msn_str = g_strdup_printf("telcfg:settings/MSN/Port%d/MSN%d", port, index);

			if (extract_number_05_50(&number_list, data, msn_str)) {
				if (type == -1) {
					type = 0;
					g_free(msn_str);
					goto set;
				}
			}
			g_free(msn_str);
		}
	}

	/* NTHotDialList */
	for (index = 0; index < 10; index++) {
		gchar *msn_str = g_strdup_printf("telcfg:settings/NTHotDialList/Number%d", index);

		if (!msn_str) {
			continue;
		}

		if (extract_number_05_50(&number_list, data, msn_str)) {
			if (type == -1) {
				type = 0;
				g_free(msn_str);
				goto set;
			}
		}
		g_free(msn_str);
	}

	/* SIP */
	for (index = 0; index < 19; index++) {
		gchar *msn_str = g_strdup_printf("telcfg:settings/SIP%d/MSN", index);

		if (extract_number_05_50(&number_list, data, msn_str)) {
			if (type == -1) {
				type = 4;
				g_free(msn_str);
				goto set;
			}
		}

		g_free(msn_str);
	}

	return;

set:
	fdebug("Setting controllers to %d", type);
	//g_settings_set_int(ri->settings, "fax-controller", type);
  ri->faxcontroller=type;
	//g_settings_set_int(ri->settings, "phone-controller", type);
  ri->phonecontroller=type;
}

/**
 * \brief Extract DECT numbers of fw 05.50
 * \param profile profile pointer
 * \param data incoming page data
 */
static void fritzbox_extract_dect_05_50(struct router_icl *ri, const gchar *data)
{
	const gchar *start = data;
	gchar *pos;
	gchar *end;
	gint size;
	gchar *fon;
	gint count = 1;
	gchar name_dect[11];

	do {
		pos = g_strstr_len(start, -1, "<td>DECT</td>");
		if (!pos) {
			break;
		}

		/* Set new start position */
		start = pos + 1;

		/* Extract previous <td>XXXX</td>, this is the phone name */
		end = g_strrstr_len(data, pos - data - 1, "\">");
		if (!end) {
			continue;
		}

		size = pos - end - 7;
		if (size <= 0) {
			continue;
		}

		memset(name_dect, 0, sizeof(name_dect));
		g_snprintf(name_dect, sizeof(name_dect), "name-dect%d", count);
		fon = (gchar*)g_slice_alloc0(size);
		g_strlcpy(fon, end + 2, size);
		fdebug("fon: '%s'", fon);
		//g_settings_set_string(ri->settings, name_dect, fon);
    ri->intern[count]=fon;
		g_slice_free1(size, fon);
		count++;
	} while (count < 7);
}

/**
 * \brief Extract XML input tag: name="TAG" ... value="VALUE"
 * \param data data to parse
 * \param tag tag to extract
 * \return tag value
 */
gchar *xml_extract_input_value(const gchar *data, gchar *tag)
{
	gchar *name = g_strdup_printf("name=\"%s\"", tag);
	gchar *start = g_strstr_len(data, -1, name);
	gchar *val_start = NULL;
	gchar *val_end = NULL;
	gchar *value = NULL;
	gssize val_size;

	g_free(name);
	if (start == NULL) {
		return NULL;
	}

	val_start = g_strstr_len(start, -1, "value=\"");
	g_assert(val_start != NULL);

	val_start += 7;

	val_end = g_strstr_len(val_start, -1, "\"");

	val_size = val_end - val_start;
	g_assert(val_size >= 0);

	value = (gchar*)g_malloc0(val_size + 1);
	memcpy(value, val_start, val_size);

	return value;
}

gboolean fritzbox_get_fax_information_06_00(struct router_icl *ri)
{
	SoupMessage *msg;
	const gchar *data;
	gsize read;
	gchar *url;
	gchar *scramble;

	url = g_strdup_printf("http://%s/fon_devices/fax_send.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-06_00-get-settings-fax.html", data, read);

	g_assert(data != NULL);

	gchar *header = xml_extract_list_value(data, (gchar*)"telcfg:settings/FaxKennung");
	if (header) {
		fdebug("Fax-Header: '%s'", header);
		//g_settings_set_string(ri->settings, "fax-header", header);
    ri->faxheaders=header;
		g_free(header);
	}

	gchar *fax_msn = xml_extract_list_value(data, (gchar*)"telcfg:settings/FaxMSN0");
	if (fax_msn) {
		if (!strcmp(fax_msn, "POTS")) {
			//gchar **numbers = g_settings_get_strv(ri->settings, "numbers");
			g_free(fax_msn);
			fax_msn = g_strdup(ri->numbers[0]);
		}
		gchar *formated_number;

		formated_number = call_format_number(ri, fax_msn, NUMBER_FORMAT_INTERNATIONAL_PLUS);

		fdebug("Fax number: '%s'", fax_msn);


		//g_settings_set_string(ri->settings, "fax-number", fax_msn);
    ri->fax_msn=fax_msn;

		//g_settings_set_string(ri->settings, "fax-ident", formated_number);
    ri->formated_number=formated_number;
		g_free(formated_number);
	}
	g_free(fax_msn);

	//g_settings_set_string(ri->settings, "fax-volume", "");
  ri->faxvolume=(gchar*)"";
	gchar *mail_active = xml_extract_list_value(data, (gchar*)"telcfg:settings/FaxMailActive");
	if (mail_active) {
		gint fax_mail_active = atoi(&mail_active[0]);

		if (fax_mail_active == 3) {
			gchar *volume;
			g_object_unref(msg);


			url = g_strdup_printf("http://%s/usb/show_usb_devices.lua", ri->host/*router_get_host(profile)*/);
			msg = soup_form_request_new(SOUP_METHOD_GET, url,
				                    "sid", ri->session_id,
				                    NULL);
			g_free(url);

			soup_session_send_message(soup_session, msg);
			if (msg->status_code != 200) {
				fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
				g_object_unref(msg);
				return FALSE;
			}
			data = msg->response_body->data;
			read = msg->response_body->length;

			//log_save_data("fritzbox-06_00-show-usb-devices.html", data, read);

			g_assert(data != NULL);

			volume = xml_extract_list_value(data, (gchar*)"name");

			if (volume) {
				fdebug("Fax-Storage-Volume: '%s'", volume);
				//g_settings_set_string(ri->settings, "fax-volume", volume);
        ri->faxvolume=volume;
			}

			g_free(mail_active);
		}
	}

	g_object_unref(msg);

	return TRUE;
}


gboolean fritzbox_get_fax_information_05_50(struct router_icl *ri)
{
	SoupMessage *msg;
	const gchar *data;
	gsize read;
	gchar *url;
	gchar *scramble;

	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "getpage", "../html/de/menus/menu2.html",
	                            "var:lang", ri->lang,
	                            "var:pagename", "fon1fxi",
	                            "var:menu", "fon",
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-05_50-get-settings-fax.html", data, read);

	g_assert(data != NULL);

	gchar *header = xml_extract_input_value(data, (gchar*)"telcfg:settings/FaxKennung");
	if (header) {
		scramble = call_scramble_number(header);
		fdebug("Fax-Header: '%s'", scramble);
		g_free(scramble);
		//g_settings_set_string(ri->settings, "fax-header", header);
    ri->faxheaders=header;
		g_free(header);
	}

	gchar *fax_msn = xml_extract_input_value(data, (gchar*)"telcfg:settings/FaxMSN0");
	if (fax_msn) {
		if (!strcmp(fax_msn, "POTS")) {
			//gchar **numbers = g_settings_get_strv(ri->settings, "numbers");
			g_free(fax_msn);
			fax_msn = g_strdup(ri->numbers[0]);
		}
		gchar *formated_number;

		formated_number = call_format_number(ri, fax_msn, NUMBER_FORMAT_INTERNATIONAL_PLUS);

		scramble = call_scramble_number(fax_msn);
		fdebug("Fax number: '%s'", scramble);
		g_free(scramble);

		//g_settings_set_string(ri->settings, "fax-number", fax_msn);
    ri->fax_msn=fax_msn;

		//g_settings_set_string(ri->settings, "fax-ident", formated_number);
    ri->formated_number=formated_number;
		g_free(formated_number);
	}
	g_free(fax_msn);

	//g_settings_set_string(ri->settings, "fax-volume", "");
  ri->faxvolume=(gchar*)"";
	gchar *active = xml_extract_input_value(data, (gchar*)"telcfg:settings/FaxMailActive");
	if (active) {
		gint fax_mail_active = atoi(&active[0]);

		if ((fax_mail_active == 2 || fax_mail_active == 3)) {
			gchar *volume = xml_extract_input_value(data, (gchar*)"ctlusb:settings/storage-part0");

			if (volume) {
				fdebug("Fax-Storage-Volume: '%s'", volume);
				//g_settings_set_string(ri->settings, "fax-volume", volume);
        ri->faxvolume=volume;
			} else {
				//g_settings_set_string(ri->settings, "fax-volume", "");
        ri->faxvolume=(gchar*)"";
			}

			g_free(active);
		}
	}

	g_object_unref(msg);

	return TRUE;
}


/**
 * \brief Get settings via lua-scripts (phone numbers/names, default controller, tam setting, fax volume/settings, prefixes, default dial port)
 * \param profile profile information structure
 * \return error code
 */
gboolean fritzbox_get_settings_05_50(struct router_icl *ri)
{
	SoupMessage *msg;
	const gchar *data;
	gint index;
	gsize read;
	gchar *url;

	fdebug("Get settings");

	/* Login */
	if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	/* Extract phone numbers */
	url = g_strdup_printf("http://%s/fon_num/fon_num_list.lua", ri->host/*router_get_host(ri)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
  printf("2!!!!!!!!!!!!!!!!!!!!!!!!!!!!! data: %s\n",(gchar*)data);
	read = msg->response_body->length;

	//log_save_data("fritzbox-05_50-get-settings-0.html", data, read);
	g_assert(data != NULL);

	gchar **numbers = xml_extract_tags(data, (gchar*)"td title=\"[^\"]*\"", (gchar*)"td");

	if (g_strv_length(numbers)) {
		ri->/*gchar **profile_*/numbers = strv_remove_duplicates(numbers);
		gint idx;

		if (g_strv_length(ri->/*profile_*/numbers)) {
			for (idx = 0; idx < g_strv_length(ri->/*profile_*/numbers); idx++) {
				fdebug("Adding MSN '%s'", ri->numbers[idx]);
			}
			//g_settings_set_strv(ri->settings, "numbers", (const gchar * const *)profile_numbers);
		}
		g_strfreev(numbers);

	}
	g_object_unref(msg);

	/* Extract phone names, default controller */
	url = g_strdup_printf("http://%s/fon_devices/fondevices_list.lua", ri->host/*router_get_host(ri)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-05_50-get-settings-1.html", data, read);
	g_assert(data != NULL);

	/* Try to detect controller */
	fritzbox_detect_controller_05_50(ri, data);

	/* Extract phone names */
	for (index = 0; index < PORT_MAX; index++) {
		gchar *value;

		value = xml_extract_list_value(data, fritzbox_phone_ports[index].name);
		if (value) {
			if (!EMPTY_STRING(value)) {
				fdebug("Port %d: '%s'", index, value);
			}
			//g_settings_set_string(ri->settings, router_phone_ports[index].name, value);
      ri->pname[index]=value; 
			g_free(value);
		}
	}

	/* FRITZ!OS 5.50 has broken the layout of DECT, therefore we must scan again for DECT */
	fritzbox_extract_dect_05_50(ri, data);

	/* Check if TAM is using USB-Stick */
	gchar *stick = xml_extract_input_value(data, (gchar*)"tam:settings/UseStick");
	if (stick && atoi(&stick[0])) {
    ri->tamstick=atoi(stick);
    //g_settings_set_int(ri->settings, "tam-stick", atoi(stick));
	} else {
    ri->tamstick=0;
    //g_settings_set_int(ri->settings, "tam-stick", 0);
	}
	g_free(stick);

	g_object_unref(msg);

	/* Extract city/country/area prefix */
	url = g_strdup_printf("http://%s/fon_num/sip_option.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-05_50-get-settings-2.html", data, read);
	g_assert(data != NULL);

	gchar *value;

	value = xml_extract_list_value(data, (gchar*)"telcfg:settings/Location/LKZ");
	if (value != NULL && strlen(value) > 0) {
		fdebug("lkz: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "country-code", value);
  ri->lkz=value;
	g_free(value);

	value = xml_extract_list_value(data, (gchar*)"telcfg:settings/Location/LKZPrefix");
	if (value != NULL && strlen(value) > 0) {
		fdebug("lkz prefix: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "international-call-prefix", value);
  ri->lkz_prefix=value;
	g_free(value);

	value = xml_extract_list_value(data, (gchar*)"telcfg:settings/Location/OKZ");
	if (value != NULL && strlen(value) > 0) {
		fdebug("okz: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "area-code", value);
  ri->okz=value;
	g_free(value);

	value = xml_extract_list_value(data, (gchar*)"telcfg:settings/Location/OKZPrefix");
	if (value != NULL && strlen(value) > 0) {
		fdebug("okz prefix: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "national-call-prefix", value);
  ri->okz_prefix=value;
	g_free(value);

	g_object_unref(msg);

	/* Extract Fax information */
	if (FIRMWARE_IS(6, 0)) {
		fritzbox_get_fax_information_06_00(ri);
	} else {
		fritzbox_get_fax_information_05_50(ri);
	}

	/* Extract default dial port */
	url = g_strdup_printf("http://%s/fon_num/dial_foncalls.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-05_50-get-settings-3.html", data, read);
	g_assert(data != NULL);

	gchar *dialport = xml_extract_list_value(data, (gchar*)"telcfg:settings/DialPort");
	if (dialport) {
		gint port = atoi(dialport);
		gint phone_port = fritzbox_find_phone_port(port);
		fdebug("Dial port: %s, phone_port: %d", dialport, phone_port);
    ri->port=phone_port;
	}
	g_free(dialport);

	g_object_unref(msg);

	/* The end - exit */
	fritzbox_logout(ri, FALSE);

	return TRUE;
}

gint number_compare_04_74(gconstpointer a, gconstpointer b)
{
	return strcmp((char*)a, (char*)b);
}

/**
 * \brief strndup phone number from fw 04.74
 * \param number_list pointer to number_list
 * \param data incoming page data
 * \param len len of string to copy
 * \return TRUE on success, otherwise FALSE
 */
gboolean copy_number_04_74(GSList **number_list, const gchar *data, gsize len)
{
	gchar *fon;

	fon = g_strndup(data, len);
	if (!EMPTY_STRING(fon) && isdigit(fon[0])) {
		if (!g_slist_find_custom(*number_list, fon, number_compare_04_74)) {
			*number_list = g_slist_prepend(*number_list, fon);
		} else {
			g_free(fon);
		}

		return TRUE;
	}

	g_free(fon);
	return FALSE;
}

/**
 * \brief Extract phone number from fw 04.74
 * \param number_list pointer to number_list
 * \param data incoming page data
 * \param msn_str string we want to lookup
 * \return TRUE on success, otherwise FALSE
 */
gboolean extract_number_04_74(GSList **number_list, const gchar *data, gchar *msn_str)
{
	gchar *fon;

	fon = xml_extract_input_value(data, msn_str);
	if (!EMPTY_STRING(fon) && isdigit(fon[0])) {
		if (!g_slist_find_custom(*number_list, fon, number_compare_04_74)) {
			*number_list = g_slist_prepend(*number_list, fon);
		} else {
			g_free(fon);
		}

		return TRUE;
	}

	g_free(fon);
	return FALSE;
}

/**
 * \brief Read MSNs of data
 * \param profile profile information structure
 * \param data data to parse for MSNs
 */
void fritzbox_extract_numbers_04_74(struct router_icl *ri, const gchar *data)
{
	gint index;
	gint type = -1;
	gint port;
	GSList *number_list = NULL;
	GSList *list;
	//gchar **numbers;
	gint counter = 0;
	gchar *skip = NULL;
	gchar *start;
	gchar *end;

	/* First read old entries */
	skip = (gchar*)strstr(data, "readFonNumbers()");

	if (skip != NULL) {
		/* POTS */
		skip = strstr(skip, "nrs.pots");
		if (skip != NULL) {
			start = strchr(skip, '"');
			end = strchr(start + 1, '"');
			if (end - start - 1 > 0) {
				copy_number_04_74(&number_list, start + 1, end - start - 1);
			}
		} else {
			skip = (gchar*)data;
		}

		/* MSN */
		for (index = 0; index < 10; index++) {
			skip = strstr(skip, "nrs.msn.push");
			if (skip != NULL) {
				start = strchr(skip, '"');
				end = strchr(start + 1, '"');
				if (end - start - 1 > 0) {
					copy_number_04_74(&number_list, start + 1, end - start - 1);
				}
				skip = end;
			}
		}

		/* SIP */
		for (index = 0; index < 19; index++) {
			skip = strstr(skip, "nrs.sip.push");
			if (skip != NULL) {
				start = strchr(skip, '"');
				end = strchr(start + 1, '"');
				if (end - start - 1 > 0) {
					copy_number_04_74(&number_list, start + 1, end - start - 1);
				}
				skip = end;
			}
		}
	}

	/* Now read the new entries */
	/* POTS first! */
	if (extract_number_04_74(&number_list, data, (gchar*)"telcfg:settings/MSN/POTS")) {
		type = 3;
	}

	/* TAM */
	for (index = 0; index < 10; index++) {
		gchar *msn_str = g_strdup_printf("tam:settings/MSN%d", index);

		extract_number_04_74(&number_list, data, msn_str);

		g_free(msn_str);
	}

	/* FAX */
	for (index = 0; index < 10; index++) {
		gchar *msn_str = g_strdup_printf("telcfg:settings/FaxMSN%d", index);

		extract_number_04_74(&number_list, data, msn_str);

		g_free(msn_str);
	}

	/* PortX-MSN */
	for (port = 0; port < 3; port++) {
		for (index = 0; index < 10; index++) {
			gchar *msn_str = g_strdup_printf("telcfg:settings/MSN/Port%d/MSN%d", port, index);

			if (extract_number_04_74(&number_list, data, msn_str)) {
				if (type == -1) {
					type = 0;
				}
			}
			g_free(msn_str);
		}
	}

	/* MSN */
	for (index = 0; index < 10; index++) {
		gchar *msn_str = g_strdup_printf("telcfg:settings/MSN/MSN%d", index);

		if (extract_number_04_74(&number_list, data, msn_str)) {
			if (type == -1) {
				type = 0;
			}
		}
		g_free(msn_str);
	}

	/* SIP */
	for (index = 0; index < 19; index++) {
		gchar *msn_str = g_strdup_printf("telcfg:settings/SIP%d/MSN", index);

		if (extract_number_04_74(&number_list, data, msn_str)) {
			if (type == -1) {
				type = 4;
			}
		}

		g_free(msn_str);
	}

	/* VoipExtensionX/NumberY */
	for (port = 0; port < 10; port++) {
		for (index = 0; index < 10; index++) {
			gchar *msn_str = g_strdup_printf("telcfg:settings/VoipExtension%d/Number%d", port, index);

			if (extract_number_04_74(&number_list, data, msn_str)) {
				if (type == -1) {
					type = 4;
				}
			}
			g_free(msn_str);
		}
	}

	ri->numbers = (gchar**)g_malloc(sizeof(gchar *) * (g_slist_length(number_list) + 1));
	for (list = number_list; list; list = list->next) {
		gchar *scramble = call_scramble_number((const gchar*)list->data);
		fdebug("Adding MSN '%s'", scramble);
		g_free(scramble);
		ri->numbers[counter++] = g_strdup((const gchar*)list->data);
	}
	ri->numbers[counter] = NULL;

	//g_settings_set_strv(ri->settings, "numbers", (const gchar * const *)numbers);

	if (type != -1) {
		fdebug("Setting controllers to %d", type);
		//g_settings_set_int(ri->settings, "fax-controller", type);
    ri->faxcontroller=type;
		//g_settings_set_int(ri->settings, "phone-controller", type);
    ri->phonecontroller=type;
	}
} // void fritzbox_extract_numbers_04_74(struct router_icl *ri, const gchar *data)

/**
 * \brief Get settings (std)
 * \param profile profile information structure
 * \return error code
 */
gboolean fritzbox_get_settings_04_74(struct router_icl *ri)
{
	SoupMessage *msg;
	const gchar *data;
	gint index;
	gsize read;
	gchar *url;
	gchar *volume = NULL;

	if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	gchar *request = g_strconcat("../html/",
	                             ri->lang,
	                             "/menus/menu2.html", NULL);

	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "getpage", request,
	                            "var:lang", ri->lang,
	                            "var:pagename", "fondevices",
	                            "var:menu", "home",
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);
	g_free(request);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
  printf("3!!!!!!!!!!!!!!!!!!!!!!!!!!!!! data: %s\n",(gchar*)data);
	read = msg->response_body->length;

	//log_save_data("fritzbox-04_74-get-settings-1.html", data, read);
	g_assert(data != NULL);

	fritzbox_extract_numbers_04_74(ri, data);

	for (index = 0; index < PORT_MAX; index++) {
		gchar *value;

		value = xml_extract_input_value(data, fritzbox_phone_ports[index].name);
		if (value != NULL && strlen(value) > 0) {
			fdebug("port %d: '%s'", index, value);
			//g_settings_set_string(ri->settings, router_phone_ports[index].name, value);
      ri->pname[index]=value; 
		}
		g_free(value);
	}
	g_object_unref(msg);

	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "getpage", "../html/de/menus/menu2.html",
	                            "var:lang", ri->lang,
	                            "var:pagename", "sipoptionen",
	                            "var:menu", "fon",
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-04_74-get-settings-2.html", data, read);
	g_assert(data != NULL);

	gchar *value;

	value = xml_extract_list_value(data, (gchar*)"telcfg:settings/Location/LKZ");
	if (value != NULL && strlen(value) > 0) {
		fdebug("lkz: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "country-code", value);
  ri->lkz=value;
	g_free(value);

	value = xml_extract_list_value(data, (gchar*)"telcfg:settings/Location/LKZPrefix");
	if (value != NULL && strlen(value) > 0) {
		fdebug("lkz prefix: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "international-call-prefix", value);
  ri->lkz_prefix=value;
	g_free(value);

	value = xml_extract_list_value(data, (gchar*)"telcfg:settings/Location/OKZ");
	if (value != NULL && strlen(value) > 0) {
		fdebug("okz: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "area-code", value);
  ri->okz=value;
	g_free(value);

	value = xml_extract_list_value(data, (gchar*)"telcfg:settings/Location/OKZPrefix");
	if (value != NULL && strlen(value) > 0) {
		fdebug("okz prefix: '%s'", value);
	}
	//g_settings_set_string(ri->settings, "national-call-prefix", value);
  ri->okz_prefix=value;
	g_free(value);

	g_object_unref(msg);

	/* Extract Fax information */
	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "getpage", "../html/de/menus/menu2.html",
	                            "var:lang", ri->lang,
	                            "var:pagename", "fon1fxi",
	                            "var:menu", "fon",
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-04_74-get-settings-fax.html", data, read);
	g_assert(data != NULL);

	gchar *header = xml_extract_input_value(data, (gchar*)"telcfg:settings/FaxKennung");
	fdebug("Fax-Header: '%s'", header);
	//g_settings_set_string(ri->settings, "fax-header", header);
  ri->faxheaders=header;
	g_free(header);

	gchar *fax_msn = xml_extract_input_value(data, (gchar*)"telcfg:settings/FaxMSN0");
	if (fax_msn) {
		gchar *formated_number = call_format_number(ri, fax_msn, NUMBER_FORMAT_INTERNATIONAL_PLUS);
		fdebug("Fax number: '%s'", fax_msn);

		//g_settings_set_string(ri->settings, "fax-number", fax_msn);
    ri->fax_msn=fax_msn;

		//g_settings_set_string(ri->settings, "fax-ident", formated_number);
    ri->formated_number=formated_number;
		g_free(formated_number);
	}
	g_free(fax_msn);

	gchar *active = xml_extract_input_value(data, (gchar*)"telcfg:settings/FaxMailActive");

	if (active && ((atoi(&active[0]) == 2) || (atoi(&active[0]) == 3))) {
		volume = xml_extract_input_value(data, (gchar*)"ctlusb:settings/storage-part0");

		if (volume) {
			fdebug("Fax-Storage-Volume: '%s'", volume);
			//g_settings_set_string(ri->settings, "fax-volume", volume);
      ri->faxvolume=volume;
		} else {
			//g_settings_set_string(ri->settings, "fax-volume", "");
      ri->faxvolume=(gchar*)"";
		}

		g_free(active);
	} else {
		//g_settings_set_string(ri->settings, "fax-volume", "");
    ri->faxvolume=(gchar*)"";
	}

	g_object_unref(msg);

	/* Extract default dial port */
	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "getpage", "../html/de/menus/menu2.html",
	                            "var:lang", ri->lang,
	                            "var:pagename", "dial",
	                            "var:menu", "fon",
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-04_74-get-settings-4.html", data, read);
	g_assert(data != NULL);

	gchar *dialport = xml_extract_input_value(data, (gchar*)"telcfg:settings/DialPort");
	if (dialport) {
		gint port = atoi(dialport);
		gint phone_port = fritzbox_find_phone_port(port);
		fdebug("Dial port: %s, phone_port: %d", dialport, phone_port);
    ri->port=phone_port;
	}
	g_free(dialport);

	/* Always use tam-stick */
	//g_settings_set_int(ri->settings, "tam-stick", 1);
  ri->tamstick=1;

	g_object_unref(msg);

	fritzbox_logout(ri, FALSE);

	return TRUE;
} // gboolean fritzbox_get_settings_04_74(struct router_icl *ri)


gboolean fritzbox_get_settings(struct router_icl *ri)
{
  fdebug("fritzbox_get_settings");
	if (fritzbox_get_settings_query(ri)) {
		return TRUE;
	}

	if (FIRMWARE_IS(6, 35)) {
		return fritzbox_get_settings_06_35(ri);
	}

	if (FIRMWARE_IS(5, 50)) {
		return fritzbox_get_settings_06_35(ri);
		return fritzbox_get_settings_05_50(ri);
	}

	if (FIRMWARE_IS(4, 0)) {
		return fritzbox_get_settings_04_74(ri);
	}

	return FALSE;
} // gboolean fritzbox_get_settings(struct router_icl *ri)

/** This is our private header, not the one used by the router! */
#define ROUTERMANAGER_JOURNAL_HEADER "Typ;Datum;Name;Rufnummer;Nebenstelle;Eigene Rufnummer;Dauer"
typedef gpointer (*csv_parse_line_func)(gpointer ptr, gchar **split,struct router_icl *ri);
#define CSV_FRITZBOX_JOURNAL_DE "Typ;Datum;Name;Rufnummer;Nebenstelle;Eigene Rufnummer;Dauer"
#define CSV_FRITZBOX_JOURNAL_EN "Type;Date;Name;Number;Extension;Outgoing Caller ID;Duration"
#define CSV_FRITZBOX_JOURNAL_EN2 "Type;Date;Name;Number;Extension;Telephone Number;Duration"
#define CSV_FRITZBOX_JOURNAL_EN3 "Type;Date;Name;Telephone number;Extension;Telephone number;Duration"

/**
 * \brief Parse data as csv
 * \param data raw data to parse
 * \param header expected header line
 * \param csv_parse_line function pointer
 * \param ptr user pointer
 * \return user pointer
 */
gpointer csv_parse_data(const gchar *data, const gchar *header, csv_parse_line_func csv_parse_line, gpointer ptr,struct router_icl *ri)
{
	gint index = 0;
	gchar sep[2];
	gchar **lines = NULL;
	gchar *pos;
	gpointer data_ptr = ptr;

	/* Safety check */
	g_assert(data != NULL);

	/* Split data to lines */
	lines = g_strsplit(data, "\n", -1);

	/* Check for separator */
	pos = g_strstr_len(lines[index], -1, "sep=");
	if (pos) {
		sep[0] = pos[4];
		index++;
	} else {
		sep[0] = ',';
	}
	sep[1] = '\0';

	/* Check header */
	if (strncmp(lines[index], header, strlen(header))) {
		fdebug("Unknown CSV-Header: '%s'", lines[index]);
		data_ptr = NULL;
		goto end;
	}

	/* Parse each line, split it and use parse function */
	while (lines[++index] != NULL) {
		gchar **split = g_strsplit(lines[index], sep, -1);

		data_ptr = csv_parse_line(data_ptr, split,ri);
    // fdebug("data_ptr: %s",*(gchar**)split);

		g_strfreev(split);
	}

end:
	g_strfreev(lines);

	/* Return ptr */
	return data_ptr;
}

/**
 * \brief Convert string (if needed) to UTF-8
 * \param text input text string
 * \param len length of string or -1 for strlen()
 * \return input string in UTF-8 (must be freed)
 */
gchar *g_convert_utf8(const gchar *text, gssize len)
{
	GError *error = NULL;
	gsize read_bytes, written_bytes;
	gchar *str = NULL;
	gssize idx;

	if (!text) {
		g_assert_not_reached();
	}

	if (len == -1) {
		len = strlen(text);
	}

	if (g_utf8_validate(text, len, NULL)) {
		return g_strndup(text, len);
	}

	/*for (idx = 0; idx < len; idx++) {
		if (text[idx] < 32 && text[idx] != '\n') {
			text[idx] = ' ';
		}
	}*/

	str = g_convert(text, len, "UTF-8", "ISO-8859-1", &read_bytes, &written_bytes, &error);
	if (str == NULL) {
		str = g_strndup(text, len);

		for (idx = 0; idx < len; idx++) {
			if ((guchar)str[idx] > 128) {
				str[idx] = '?';
			}
		}
	}

	if (error) {
		g_error_free(error);
	}

	return str;
}

/**
 * \brief Sort calls (compares two calls based on date/time)
 * \param a call a
 * \param b call b
 * \return see strncmp
 */
gint call_sort_by_date(gconstpointer a, gconstpointer b)
{
	struct call *call_a = (struct call *) a;
	struct call *call_b = (struct call *) b;
	gchar *number_a = NULL;
	gchar *number_b = NULL;
	gchar part_time_a[7];
	gchar part_time_b[7];
	gint ret = 0;

	if (!call_a || !call_b) {
		return 0;
	}

	if (call_a) {
		number_a = call_a->date_time;
	}

	if (call_b) {
		number_b = call_b->date_time;
	}

	/* Compare year */
	ret = strncmp(number_a + 6, number_b + 6, 2);
	if (ret == 0) {
		/* Compare month */
		ret = strncmp(number_a + 3, number_b + 3, 2);
		if (ret == 0) {
			/* Compare day */
			ret = strncmp(number_a, number_b, 2);
			if (ret == 0) {
				/* Extract time */
				memset(part_time_a, 0, sizeof(part_time_a));
				g_strlcpy(part_time_a, number_a + 9, 6);

				/* Extract time */
				memset(part_time_b, 0, sizeof(part_time_b));
				g_strlcpy(part_time_b, number_b + 9, 6);

				ret = g_utf8_collate(part_time_a, part_time_b);
			}
		}
	}

	return -ret;
}


/**
 * \brief Add call to journal
 * \param journal call list
 * \param type call type
 * \param date_time date and time of call
 * \param remote_name remote caller name
 * \param remote_number remote caller number
 * \param local_name local caller name
 * \param local_number local caller number
 * \param duration call duration
 * \param priv private data
 * \return new call list with appended call structure
 */
GSList *call_add(GSList *journal, gint type, const gchar *date_time, const gchar *remote_name, const gchar *remote_number, const gchar *local_name, const gchar *local_number, const gchar *duration, gpointer priv)
{
	GSList *list = journal;
	struct call *call = NULL;

	/* Search through list and find duplicates */
	for (list = journal; list != NULL; list = list->next) {
		call = (struct call*)list->data;

		/* Easier compare method, we are just interested in the complete date_time, remote_number and type field */
		if (!strcmp(call->date_time, date_time) && !strcmp(call->remote->number, remote_number)) {
			if (call->type == type) {
				/* Call with the same type already exists, return unchanged journal */
				return journal;
			}

			/* Found same call with different type (voice/fax): merge them */
			if (type == CALL_TYPE_VOICE || type == CALL_TYPE_FAX) {
				call->type = type;
				call->priv = (gchar*)priv;

				return journal;
			}
		}
	}

	/* Create new call structure */
	call = g_slice_new0(struct call);

	/* Set entries */
	call->type = type;
	call->date_time = date_time ? g_strdup(date_time) : g_strdup("");
	call->remote = g_slice_new0(struct contact);
	call->remote->image = NULL;
	call->remote->name = remote_name ? g_convert_utf8(remote_name, -1) : g_strdup("");
	call->remote->number = remote_number ? g_strdup(remote_number) : g_strdup("");
	call->local = g_slice_new0(struct contact);
	call->local->name = local_name ? g_convert_utf8(local_name, -1) : g_strdup("");
	call->local->number = local_number ? g_strdup(local_number) : g_strdup("");
	call->duration = duration ? g_strdup(duration) : g_strdup("");

	/* Extended */
	call->remote->company = g_strdup("");
	call->remote->city = g_strdup("");
	call->priv = (gchar*)priv;

	/* Append call sorted to the list */
	list = g_slist_insert_sorted(journal, call, call_sort_by_date);

	/* Return new call list */
	return list;
}

/**
 * \brief Parse FRITZ!Box "Anruferliste"
 * \param ptr pointer to journal
 * \param split splitted line
 * \return pointer to journal with attached call line
 */
static inline gpointer csv_parse_fritzbox(gpointer ptr, gchar **split,struct router_icl *ri)
{
	GSList *list = (GSList*)ptr;

	if (g_strv_length(split) == 7) {
		gint call_type = 0;

		switch (atoi(split[0])) {
		case 1:
			call_type = CALL_TYPE_INCOMING;
			break;
		case 2:
			call_type = CALL_TYPE_MISSED;
			break;
		case 3: {
//			struct profile *profile = profile_get_active();

			if (FIRMWARE_IS(4, 74)) {
				call_type = CALL_TYPE_BLOCKED;
			} else {
				call_type = CALL_TYPE_OUTGOING;
			}
			break;
		}
		case 4:
			call_type = CALL_TYPE_OUTGOING;
			break;
		}

		list = call_add(list, call_type, split[1], split[2], split[3], split[4], split[5], split[6], NULL);
    // printf("%i %s %s %s %s %s %s\n",call_type, split[1], split[2], split[3], split[4], split[5], split[6]);
	}

	return list;
} // static inline gpointer csv_parse_fritzbox(gpointer ptr, gchar **split,struct router_icl *ri)

/**
 * \brief Parse journal data as csv
 * \param data raw data to parse
 * \return call list
 */
GSList *csv_parse_fritzbox_journal_data(GSList *list, const gchar *data,struct router_icl *ri)
{
	GSList *new_list = NULL;

	new_list = (GSList*)csv_parse_data(data, CSV_FRITZBOX_JOURNAL_DE, csv_parse_fritzbox, list,ri);
	if (!new_list) {
		new_list = (GSList*)csv_parse_data(data, CSV_FRITZBOX_JOURNAL_EN, csv_parse_fritzbox, list,ri);
		if (!new_list) {
			new_list = (GSList*)csv_parse_data(data, CSV_FRITZBOX_JOURNAL_EN2, csv_parse_fritzbox, list,ri);
			if (!new_list) {
				new_list = (GSList*)csv_parse_data(data, CSV_FRITZBOX_JOURNAL_EN3, csv_parse_fritzbox, list,ri);
			}
		}
	}

	if (!new_list) {
		// log_save_data("fritzbox-journal.csv", data, strlen(data));
	}

	/* Return call list */
	return new_list;
}

struct ftp {
	gchar *server;
	gint code;
	gchar *response;
	GIOChannel *control;
	GIOChannel *data;
	GTimer *timer;
};

/**
 * \brief Open FTP port channel
 * \param server server name
 * \param port port number
 * \return io channel for given server:port
 */
static GIOChannel *ftp_open_port(gchar *server, gint port)
{
	GSocket *socket = NULL;
	GInetAddress *inet_address = NULL;
	GSocketAddress *sock_address = NULL;
	GError *error = NULL;
	GResolver *resolver = NULL;
	GList *list = NULL;
	GList *tmp;
	GIOChannel *io_channel;
	gint sock;

	resolver = g_resolver_get_default();
	list = g_resolver_lookup_by_name(resolver, server, NULL, NULL);
	g_object_unref(resolver);

	if (list == NULL) {
		g_warning("Cannot resolve ip from hostname: %s!", server);
		return NULL;
	}

	/* We need a IPV4 connection */
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		if (g_inet_address_get_family((GInetAddress*)tmp->data) == G_SOCKET_FAMILY_IPV4) {
			inet_address = (GInetAddress*)tmp->data;
		}
	}

	if (inet_address == NULL) {
		g_warning("Could not get ipv4 inet address from string: '%s'", server);
		g_object_unref(socket);
		g_resolver_free_addresses(list);
		return NULL;
	}

	sock_address = g_inet_socket_address_new(inet_address, port);
	if (sock_address == NULL) {
		g_warning("Could not create sock address on port %d", port);
		g_object_unref(socket);
		g_resolver_free_addresses(list);
		return NULL;
	}

	error = NULL;
	socket = g_socket_new(g_inet_address_get_family(inet_address), G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, &error);

	error = NULL;
	if (g_socket_connect(socket, sock_address, NULL, &error) == FALSE) {
		g_warning("Could not connect to socket. Error: %s", error->message);
		g_error_free(error);
		g_object_unref(socket);
		g_resolver_free_addresses(list);
		return NULL;
	}

	sock = g_socket_get_fd(socket);

#ifdef G_OS_WIN32
	io_channel = g_io_channel_win32_new_socket(sock);
#else
	io_channel = g_io_channel_unix_new(sock);
#endif
	g_io_channel_set_encoding(io_channel, NULL, NULL);
	g_io_channel_set_buffered(io_channel, TRUE);

#ifdef FTP_DEBUG
	fdebug("ftp_open_port(): connected on port %d", port);
#endif

	return io_channel;
}

/**
 * \brief Read FTP control response from channel
 * \param channel open ftp io control channel
 * \param len pointer to store the data length to
 * \return data response message or NULL on error
 */
gboolean ftp_read_control_response(struct ftp *client)
{
	GError *error = NULL;
	GIOStatus io_status;
	gsize length;
	gchar match[5];
	gboolean multiline_start = FALSE;
	gboolean multiline_end = FALSE;

#ifdef FTP_DEBUG
	fdebug("Wait for control response");
#endif

	/* Clear previous response message */
	if (client->response) {
		g_free(client->response);
		client->response = NULL;
	}

	g_timer_start(client->timer);

	do {
		io_status = g_io_channel_read_line(client->control, &client->response, &length, NULL, &error);

		if (io_status == G_IO_STATUS_AGAIN) {
			g_usleep(500);
			continue;
		} else if (io_status != G_IO_STATUS_NORMAL) {
			g_warning("Got: io status %d, Error: %s", io_status, error->message);
			break;
		}

		if (!multiline_start) {
			client->code = g_ascii_strtoll(client->response, NULL, 10);
#ifdef FTP_DEBUG
			fdebug("Response: '%s'", client->response);
#endif
			if (client->response[3] == '-') {
				match[0] = client->response[0];
				match[1] = client->response[1];
				match[2] = client->response[2];
				match[3] = ' ';
				match[4] = '\0';

				multiline_start = TRUE;
			}
		} else {
#ifdef FTP_DEBUG
			fdebug("Response: '%s'", client->response);
#endif
			if (!strncmp(client->response, match, 4)) {
				multiline_end = TRUE;
			}
		}
	} while ((g_timer_elapsed(client->timer, NULL) < 5) && (!client->response || (multiline_start && !multiline_end)));

	g_timer_stop(client->timer);

	return client->response != NULL;
}


/**
 * \brief Initialize ftp structure
 * \param server server host name
 * \return ftp structure or NULL on error
 */
struct ftp *ftp_init(const gchar *server)
{
	struct ftp *client = g_slice_new0(struct ftp);

	client->server = g_strdup(server);
	client->control = ftp_open_port(client->server, 21);
	if (!client->control) {
		g_warning("Could not connect to FTP-Port 21");
		g_free(client->server);
		g_slice_free(struct ftp, client);
		return NULL;
	}

	client->timer = g_timer_new();

	/* Read welcome message */
	ftp_read_control_response(client);

#ifdef FTP_DEBUG
	fdebug("ftp_init() done");
#endif

	return client;
}

/**
 * \brief Send FTP command through io channel
 * \param client ftp client structure
 * \param command FTP command
 * \return TRUE if data is available, FALSE on error
 */
gboolean ftp_send_command(struct ftp *client, gchar *command)
{
	gchar *ftp_command;
	GIOStatus io_status;
	GError *error = NULL;
	gsize written;

	ftp_command = g_strconcat(command, "\r\n", NULL);

	io_status = g_io_channel_write_chars(client->control, ftp_command, strlen(ftp_command), &written, &error);
	g_free(ftp_command);
	if (io_status != G_IO_STATUS_NORMAL) {
		g_warning("Write error: %d", io_status);
		return FALSE;
	}
	g_io_channel_flush(client->control, NULL);

	return ftp_read_control_response(client);
}

/**
 * \brief Login to FTP server
 * \param client ftp client structure
 * \param user username
 * \param password user password
 * \return TRUE if login was successfull, otherwise FALSE
 */
gboolean ftp_login(struct ftp *client, const gchar *user, const gchar *password)
{
	gchar *cmd;
	gboolean login = FALSE;

	cmd = g_strconcat("USER ", user, NULL);
#ifdef FTP_DEBUG
	fdebug("ftp_login(): %s", cmd);
#endif
	ftp_send_command(client, cmd);
	g_free(cmd);

	if (client->code == 331) {
		cmd = g_strconcat("PASS ", password, NULL);
#ifdef FTP_DEBUG
		fdebug("ftp_login(): PASS <xxxx>");
#endif
		ftp_send_command(client, cmd);
		g_free(cmd);

		if (client->code == 230) {
			login = TRUE;
		}
	} else if (client->code == 230) {
		/* Already logged in */
		login = TRUE;
	}

	return login;
}

/**
 * \brief Emit signal: message
 * \param title title text
 * \param message message text
 */
void emit_message(gchar *title, gchar *message)
{
	g_signal_emit(app_object, app_object_signals[ACB_MESSAGE], 0, g_strdup(title), g_strdup(message));
}

/**
 * \brief Shutdown ftp structure (close sockets and free memory)
 * \param client ftp client structure
 * \return TRUE on success, otherwise FALSE
 */
gboolean ftp_shutdown(struct ftp *client)
{
#ifdef FTP_DEBUG
	fdebug("ftp_shutdown(): start");
#endif

	g_return_val_if_fail(client != NULL, FALSE);

	g_timer_destroy(client->timer);

#ifdef FTP_DEBUG
	fdebug("ftp_shutdown(): free");
#endif
	g_free(client->server);
	g_free(client->response);

#ifdef FTP_DEBUG
	fdebug("ftp_shutdown(): shutdown");
#endif

	if (client->control) {
		g_io_channel_shutdown(client->control, FALSE, NULL);
		g_io_channel_unref(client->control);
	}

	if (client->data) {
		g_io_channel_shutdown(client->data, FALSE, NULL);
		g_io_channel_unref(client->data);
	}

#ifdef FTP_DEBUG
	fdebug("ftp_shutdown(): free");
#endif
	g_slice_free(struct ftp, client);

#ifdef FTP_DEBUG
	fdebug("ftp_shutdown(): done");
#endif

	return TRUE;
}

/**
 * \brief Switch FTP transfer to passive mode
 * \param client ftp client structure
 * \return result, TRUE for success, FALSE on error
 */
gboolean ftp_passive(struct ftp *client)
{
	gchar *pos;
	gint data_port;
	guint v[6];

#ifdef FTP_DEBUG
	fdebug("ftp_passive(): request");
#endif

	if (client->data) {
#ifdef FTP_DEBUG
		fdebug("Data channel already open");
#endif
		g_io_channel_shutdown(client->data, FALSE, NULL);
		g_io_channel_unref(client->data);
		client->data = NULL;
#ifdef FTP_DEBUG
		fdebug("ftp_passive(): data is NULL now");
#endif
	}

#ifdef FTP_DEBUG
	fdebug("ftp_passive(): EPSV");
#endif
	ftp_send_command(client, (gchar*)"EPSV");

	if (client->code == 229) {
		pos = strchr(client->response, '|');
		if (!pos) {
			return FALSE;
		}

		pos += 3;
		sscanf(pos, "%u", &data_port);
	} else {
#ifdef FTP_DEBUG
		fdebug("ftp_passive(): PASV");
#endif
		ftp_send_command(client, (gchar*)"PASV");

		if (client->code != 227) {
			return FALSE;
		}
		pos = strchr(client->response, '(');
		if (!pos) {
			return FALSE;
		}

		pos++;
		sscanf(pos, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);

#ifdef FTP_DEBUG
		//fdebug("ftp_passive(): v0 %d, v1: %d", v[0], v[1]);
#endif
		data_port = v[0] * 256 + v[1];
	}

#ifdef FTP_DEBUG
	fdebug("ftp_passive(): data_port: %d", data_port);
#endif

	client->data = ftp_open_port(client->server, data_port);

	return client->data != NULL;
}

/**
 * \brief Read FTP data response from channel
 * \param channel open ftp io data channel
 * \param len pointer to store the data length to
 * \return data response message or NULL on error
 */
gchar *ftp_read_data_response(GIOChannel *channel, gsize *len)
{
	GError *error = NULL;
	GIOStatus io_status;
	gchar buffer[32768];
	gsize read;
	gchar *data;
	gsize data_size = 0;
	goffset data_offset = 0;

	data = NULL;

	while (1) {
		memset(buffer, 0, sizeof(buffer));
		io_status = g_io_channel_read_chars(channel, buffer, sizeof(buffer), &read, &error);

		if (io_status == G_IO_STATUS_NORMAL) {
			data_size += read;
			data = (gchar*)g_realloc(data, data_size + 1);
			memcpy(data + data_offset, buffer, read);
			data_offset += read;
			data[data_offset] = '\0';
		} else if (io_status == G_IO_STATUS_AGAIN) {
			continue;
		} else {
			break;
		}
	}

	if (len) {
		*len = data_offset;
	}

	return data;
}

/**
 * \brief List FTP directory
 * \param client ftp client structure
 * \param dir directory name
 * \return directory listing
 */
gchar *ftp_list_dir(struct ftp *client, const gchar *dir)
{
	gchar *cmd = g_strconcat("CWD ", dir, NULL);
	gchar *response = NULL;

#ifdef FTP_DEBUG
	fdebug("ftp_list_dir(): %s", cmd);
#endif
	ftp_send_command(client, cmd);
	g_free(cmd);

#ifdef FTP_DEBUG
	fdebug("ftp_list_dir(): NLST");
#endif
	ftp_send_command(client, (gchar*)"NLST");

	if (client->code == 150) {
		response = ftp_read_data_response(client->data, NULL);
	}

	return response;
}


#define _(text) gettext(text)
/**
 * \brief Load faxbox and add it to journal
 * \param journal journal call list
 * \return journal list with added faxbox
 */
GSList *fritzbox_load_faxbox(router_icl *ri,GSList *journal)
{
	//struct profile *profile = profile_get_active();
	struct ftp *client;
	//gchar *user = router_get_ftp_user(profile);
	gchar *response;
	gchar *path;
	gchar *volume_path;

	client = ftp_init(ri->host/*router_get_host(profile)*/);
	if (!client) {
		return journal;
	}

	if (!ftp_login(client, ri->ftpusr, ri->ftppwd/*router_get_ftp_password(profile)*/)) {
		g_warning("Could not login to router ftp");
		emit_message(_("FTP Login failed"), _("Please check your ftp credentials"));
		ftp_shutdown(client);
		return journal;
	}

	if (!ftp_passive(client)) {
		g_warning("Could not switch to passive mode");
		ftp_shutdown(client);
		return journal;
	}

	volume_path = ri->faxvolume;//g_settings_get_string(profile->settings, "fax-volume");
	path = g_build_filename(volume_path, "FRITZ/faxbox/", NULL);
	g_free(volume_path);
	response = ftp_list_dir(client, path);
	if (response) {
		gchar **split;
		gint index;

		split = g_strsplit(response, "\n", -1);

		for (index = 0; index < g_strv_length(split); index++) {
			gchar date[9];
			gchar time[6];
			gchar remote_number[32];
			gchar *start;
			gchar *pos;
			gchar *full;
			gchar *number;

			start = strstr(split[index], "Telefax");
			if (!start) {
				continue;
			}

			full = g_strconcat(path, split[index], NULL);
			strncpy(date, split[index], 8);
			date[8] = '\0';

			strncpy(time, split[index] + 9, 5);
			time[2] = ':';
			time[5] = '\0';

			pos = strstr(start + 8, ".");
			strncpy(remote_number, start + 8, pos - start - 8);
			remote_number[pos - start - 8] = '\0';

			if (isdigit(remote_number[0])) {
				number = remote_number;
			} else {
				number = (gchar*)"";
			}

			journal = call_add(journal, CALL_TYPE_FAX, g_strdup_printf("%s %s", date, time), "", number, ("Telefax"), "", "0:01", g_strdup(full));
			g_free(full);
		}

		g_strfreev(split);

		g_free(response);
	}
	g_free(path);

	ftp_shutdown(client);

	return journal;
}

/**
 * \brief Load fax reports and add them to the journal
 * \param profile profile structure
 * \param journal journal list pointer
 * \return new journal list with attached fax reports
 */
GSList *router_load_fax_reports(router_icl *ri, GSList *journal)
{
	GDir *dir;
	GError *error = NULL;
	const gchar *file_name;
	gchar *dir_name = ri->faxreportdir; // g_settings_get_string(profile->settings, "fax-report-dir");

	if (!dir_name) {
		return journal;
	}

	dir = g_dir_open(dir_name, 0, &error);
	if (!dir) {
		fdebug("Could not open fax report directory");
		return journal;
	}

	while ((file_name = g_dir_read_name(dir))) {
		gchar *uri;
		gchar **split;
		gchar *date_time;

		if (strncmp(file_name, "fax-report", 10)) {
			continue;
		}

		split = g_strsplit(file_name, "_", -1);
		if (g_strv_length(split) != 9) {
			g_strfreev(split);
			continue;
		}

		uri = g_build_filename(dir_name, file_name, NULL);

		date_time = g_strdup_printf("%s.%s.%s %2.2s:%2.2s", split[3], split[4], split[5] + 2, split[6], split[7]);
		journal = call_add(journal, CALL_TYPE_FAX_REPORT, date_time, "", split[2], ("Fax-Report"), split[1], "0:01", g_strdup(uri));

		g_free(uri);
		g_strfreev(split);
	}

	return journal;
}

/**
 * \brief Load voice records and add them to the journal
 * \param profile profile structure
 * \param journal journal list pointer
 * \return new journal list with attached fax reports
 */
GSList *router_load_voice_records(struct router_icl *ri, GSList *journal)
{
	GDir *dir;
	GError *error = NULL;
	const gchar *file_name;
	const gchar *user_plugins = g_get_user_data_dir();
	gchar *dir_name = g_build_filename(user_plugins, "roger", G_DIR_SEPARATOR_S, NULL);

	if (!dir_name) {
		return journal;
	}

	dir = g_dir_open(dir_name, 0, &error);
	if (!dir) {
		fdebug("Could not open voice records directory");
		return journal;
	}

	while ((file_name = g_dir_read_name(dir))) {
		gchar *uri;
		gchar **split;
		gchar *date_time;
		gchar *num;

		/* %2.2d.%2.2d.%4.4d-%2.2d-%2.2d-%s-%s.wav",
			time_val->tm_mday, time_val->tm_mon, 1900 + time_val->tm_year,
			time_val->tm_hour, time_val->tm_min, connection->source, connection->target);
		*/

		if (!strstr(file_name, ".wav")) {
			continue;
		}

		split = g_strsplit(file_name, "-", -1);
		if (g_strv_length(split) != 5) {
			g_strfreev(split);
			continue;
		}

		uri = g_build_filename(dir_name, file_name, NULL);
		num = split[4];
		num[strlen(num) - 4] = '\0';

		//date_time = g_strdup_printf("%s.%s.%s %2.2s:%2.2s", split[3], split[4], split[5] + 2, split[6], split[7]);
		date_time = g_strdup_printf("%s %2.2s:%2.2s", split[0], split[1], split[2]);
		journal = call_add(journal, CALL_TYPE_RECORD, date_time, "", num, ("Record"), split[3], "0:01", g_strdup(uri));

		g_free(uri);
		g_strfreev(split);
	}

	return journal;
}


/**
 * \brief Load file
 * \param name file name
 * \param size pointer to store length of data to
 * \return file data pointer
 */
gchar *file_load(gchar *name, gsize *size)
{
	GFile *file;
	GFileInfo *file_info;
	goffset file_size;
	gchar *data = NULL;
	GFileInputStream *input_stream = NULL;

	file = g_file_new_for_path(name);
	if (!g_file_query_exists(file, NULL)) {
		return NULL;
	}

	file_info = g_file_query_info(file, G_FILE_ATTRIBUTE_STANDARD_SIZE, G_FILE_QUERY_INFO_NONE, NULL, NULL);
	file_size = g_file_info_get_size(file_info);
	if (file_size) {
		data = (gchar*)g_malloc0(file_size + 1);
		input_stream = g_file_read(file, NULL, NULL);

		g_input_stream_read_all(G_INPUT_STREAM(input_stream), data, file_size, size, NULL, NULL);

		g_object_unref(input_stream);
	}
	g_object_unref(file_info);
	g_object_unref(file);

	return data;
}

/**
 * \brief Parse routermanager
 * \param ptr pointer to journal
 * \param split splitted line
 * \return pointer to journal with attached call line
 */
static inline gpointer csv_parse_routermanager(gpointer ptr, gchar **split,router_icl *ri)
{
	GSList *list = (GSList*)ptr;

	if (g_strv_length(split) == 7) {
		list = call_add(list, atoi(split[0]), split[1], split[2], split[3], split[4], split[5], split[6], NULL);
	}

	return list;
}

/**
 * \brief Parse journal data as csv
 * \param data raw data to parse
 * \return call list
 */
GSList *csv_parse_journal_data(GSList *list, const gchar *data,router_icl *ri)
{
	list = (GSList*)csv_parse_data(data, ROUTERMANAGER_JOURNAL_HEADER, csv_parse_routermanager, list,ri);

	/* Return call list */
	return list;
}

/**
 * \brief Load saved journal
 * \param journal list pointer to fill
 * \return filled journal list
 */
GSList *csv_load_journal(GSList *journal,router_icl *ri)
{
	gchar *file_name;
	gchar *file_data;
	GSList *list = journal;
	//struct profile *profile = profile_get_active();
  printf("1 csv_load_journal\n");

	//file_name = g_build_filename(g_get_user_data_dir(), "routermanager", profile->name, "journal.csv", NULL);
  file_name = g_strconcat(ri->faxreportdir,"/journal.csv",0);
	file_data = file_load(file_name, NULL);
  printf("2 csv_load_journal\n");
	g_free(file_name);

	if (file_data) {
		list = csv_parse_journal_data(journal, file_data,ri);
		g_free(file_data);
	}
  printf("3 csv_load_journal\n");

	return list;
}


/**
 * \brief Save journal to local storage
 * \param journal journal list pointer
 * \param filename file name to store journal to
 * \return TRUE on success, otherwise FALSE
 */
gboolean csv_save_journal_as(GSList *journal, gchar *file_name)
{
	GSList *list;
	struct call *call;
	FILE *file;

	/* Open output file */
	file = fopen(file_name, "wb+");

	if (!file) {
		fdebug("Could not open journal output file %s", file_name);
		return FALSE;
	}

	fprintf(file, "sep=;\n");
	fprintf(file, ROUTERMANAGER_JOURNAL_HEADER);
	fprintf(file, "\n");

	for (list = journal; list; list = list->next) {
		call = (struct call*)list->data;

		if (call->type != CALL_TYPE_INCOMING && call->type != CALL_TYPE_OUTGOING && call->type != CALL_TYPE_MISSED && call->type != CALL_TYPE_BLOCKED) {
			continue;
		}

		gchar *name = g_convert(call->remote->name, -1, "iso-8859-1", "UTF-8", NULL, NULL, NULL);
		fprintf(file, "%d;%s;%s;%s;%s;%s;%s\n",
		        call->type,
		        call->date_time,
		        name,
		        call->remote->number,
		        call->local->name,
		        call->local->number,
		        call->duration);
		g_free(name);
	}

	fclose(file);

	return TRUE;
}

/**
 * \brief Save journal to local storage
 * \param journal journal list pointer
 * \return TRUE on success, otherwise FALSE
 */
gboolean csv_save_journal(GSList* journal, router_icl *ri)
{
	//struct profile *profile = profile_get_active();
	//gchar *dir;
	gchar *file_name;
	gboolean ret;
  printf("0 csv_save_journal\n");

	/* Build directory name and create it (if needed) */
  /*
	dir = g_build_filename(g_get_user_data_dir(), "routermanager", profile->name, NULL);
	g_mkdir_with_parents(dir, 0700);

	file_name = g_build_filename(dir, "journal.csv", NULL);
  **/
  printf("%s\n",ri->faxreportdir);
  file_name = g_strconcat(ri->faxreportdir,"/journal.csv",0);
  printf("1 csv_save_journal\n");

	ret = csv_save_journal_as(journal, file_name);
  printf("2 csv_save_journal\n");

	//g_free(dir);
  printf("3 csv_save_journal\n");
	g_free(file_name);
  printf("4 csv_save_journal\n");

	return ret;
}

/**
 * \brief Emit signal: contact-process
 * \param contact contact which needs to be processed
 */
void emit_contact_process(struct contact *contact)
{
	g_signal_emit(app_object, app_object_signals[ACB_CONTACT_PROCESS], 0, contact);
}

/**
 * \brief Emit signal: journal-loaded
 * \param journal new journal needs to be handled by application
 */
void emit_journal_loaded(GSList *journal)
{
	if (app_object) {
		g_signal_emit(app_object, app_object_signals[ACB_JOURNAL_LOADED], 0, journal);
	}
}

/**
 * \brief Router needs to process a new loaded journal (emit journal-process signal and journal-loaded)
 * \param journal journal list
 */
void router_process_journal(GSList *journal,router_icl *ri)
{
	GSList *list;
  printf("1 router_process_journal\n");

	/* Parse offline journal and combine new entries */
	journal = csv_load_journal(journal,ri);
  printf("2 router_process_journal\n");


	/* Store it back to disk */
  for (list = journal; list; list = list->next) {
    struct call *c = (struct call*)list->data;
    gchar *name = g_convert(c->remote->name, -1, "iso-8859-1", "UTF-8", NULL, NULL, NULL);
    printf("%d;%s;%s;%s;%s;%s;%s\n",
        c->type,
        c->date_time,
        name,
        c->remote->number,
        c->local->name,
        c->local->number,
        c->duration);
  }
  printf("4 router_process_journal\n");
	csv_save_journal(journal,ri);
  printf("3 router_process_journal\n");
  if (0) {

    /* Try to lookup entries in address book */
    for (list = journal; list; list = list->next) {
      struct call *c = (struct call*)list->data;
      printf("call-> remote: %s %s\n",c->remote->name,c->remote->number);
      emit_contact_process(c->remote);
    }
    printf("5 router_process_journal\n");
  }

	/* Emit "journal-loaded" signal */
	emit_journal_loaded(journal);
  printf("6 router_process_journal\n");

}

/**
 * \brief Get file of FTP
 * \param client ftp client structure
 * \param file file to download
 * \param len pointer to store the file size to
 * \return file data or NULL on error
 */
gchar *ftp_get_file(struct ftp *client, const gchar *file, gsize *len)
{
	gchar *cmd = g_strconcat("RETR ", file, NULL);
	gchar *response = NULL;

	if (len) {
		*len = 0;
	}

#ifdef FTP_DEBUG
	fdebug("ftp_get_file(): TYPE I");
#endif
	ftp_send_command(client, (gchar*)"TYPE I");

#ifdef FTP_DEBUG
	fdebug("ftp_get_file(): %s", cmd);
#endif
	ftp_send_command(client, cmd);
	g_free(cmd);

	if (client->code == 150) {
		response = ftp_read_data_response(client->data, len);
		ftp_read_control_response(client);
	}

	return response;
}

/**
 * \brief Parse voice data structure and add calls to journal
 * \param journal journal call list
 * \param data meta data to parse voice data for
 * \param len length of data
 * \return journal call list with voicebox data
 */
static GSList *fritzbox_parse_voice_data(GSList *journal, const gchar *data, gsize len)
{
	gint index;

	for (index = 0; index < len / sizeof(struct voice_data); index++) {
		struct voice_data *voice_data = (struct voice_data *)(data + index * sizeof(struct voice_data));
		gchar date_time[15];

		/* Skip user/standard welcome message */
		if (!strncmp(voice_data->file, "uvp", 3)) {
			continue;
		}

		if (voice_data->header == 0x5C010000) {
			voice_data->header = GINT_TO_BE(voice_data->header);
			voice_data->type = GINT_TO_BE(voice_data->type);
			voice_data->sub_type = GUINT_TO_BE(voice_data->sub_type);
			voice_data->size = GUINT_TO_BE(voice_data->size);
			voice_data->duration = GUINT_TO_BE(voice_data->duration);
			voice_data->status = GUINT_TO_BE(voice_data->status);
		}

		snprintf(date_time, sizeof(date_time), "%2.2d.%2.2d.%2.2d %2.2d:%2.2d", voice_data->day, voice_data->month, voice_data->year,
		         voice_data->hour, voice_data->minute);
		journal = call_add(journal, CALL_TYPE_VOICE, date_time, "", voice_data->remote_number, "", voice_data->local_number, "0:01", g_strdup(voice_data->file));
	}

	return journal;
}


/**
 * \brief Load voicebox and add it to journal
 * \param journal journal call list
 * \return journal list with added voicebox
 */
GSList *fritzbox_load_voicebox(router_icl *ri,GSList *journal)
{
	struct ftp *client;
	gchar *path;
	gint index;
	//struct profile *profile = profile_get_active();
	gchar *user = ri->ftpusr;//router_get_ftp_user(profile);
	gchar *volume_path;

	client = ftp_init(ri->host/*router_get_host(profile)*/);
	if (!client) {
		g_warning("Could not init ftp connection. Please check that ftp is enabled");
		return journal;
	}

	if (!ftp_login(client, user, ri->ftppwd/*router_get_ftp_password(profile)*/)) {
		g_warning("Could not login to router ftp");
		emit_message(_("FTP Login failed"), _("Please check your ftp credentials"));
		ftp_shutdown(client);
		return journal;
	}

	volume_path = ri->faxvolume;//g_settings_get_string(profile->settings, "fax-volume");
	path = g_build_filename(volume_path, "FRITZ/voicebox/", NULL);
	g_free(volume_path);

	for (index = 0; index < 5; index++) {
		gchar *file = g_strdup_printf("%smeta%d", path, index);
		gchar *file_data;
		gsize file_size = 0;

		if (!ftp_passive(client)) {
			g_warning("Could not switch to passive mode");
			break;
		}

		file_data = ftp_get_file(client, file, &file_size);
		g_free(file);

		if (file_data && file_size) {
			voice_boxes[index].len = file_size;
			voice_boxes[index].data = g_malloc(voice_boxes[index].len);
			memcpy(voice_boxes[index].data, file_data, file_size);
			journal = fritzbox_parse_voice_data(journal, file_data, file_size);
			g_free(file_data);
		} else {
			g_free(file_data);
			break;
		}
	}
	g_free(path);

	ftp_shutdown(client);

	return journal;
}


/**
 * \brief Journal callback function (parse data and emit "journal-process"/"journal-loaded" signals, logout)
 * \param session soup session
 * \param msg soup message
 * \param user_data poiner to profile structure
 */
void fritzbox_journal_05_50_cb(SoupSession *session, SoupMessage *msg, void *user_data)
{
	GSList *journal = NULL;
  router_icl *ri=(router_icl*)user_data;
  printf("hier host: %s\n",ri->host);

	/* Parse online journal */
	journal = csv_parse_fritzbox_journal_data(journal, msg->response_body->data,(struct router_icl*)ri);
  printf(" 1 fritzbox_journal_05_05_cb\n");

	/* Load and add faxbox */
	journal = fritzbox_load_faxbox((struct router_icl*)ri,journal);
  printf(" 2 fritzbox_journal_05_05_cb\n");

	/* Load and add voicebox */
	journal = fritzbox_load_voicebox((struct router_icl*)ri,journal);
  printf(" 3 fritzbox_journal_05_05_cb\n");

	/* Load fax reports */
	journal = router_load_fax_reports((struct router_icl*)ri, journal);
  printf(" 4 fritzbox_journal_05_05_cb\n");

	/* Load voice records */
	journal = router_load_voice_records((struct router_icl*)ri, journal);
  printf(" 5 fritzbox_journal_05_05_cb\n");

	/* Process journal list */
	router_process_journal(journal,(struct router_icl*)ri);
  printf(" 6 fritzbox_journal_05_05_cb\n");

	/* Logout */
  fritzbox_logout((struct router_icl*)ri, FALSE);
  printf(" Ende fritzbox_journal_05_05_cb\n");
} // void fritzbox_journal_05_50_cb(SoupSession *session, SoupMessage *msg, void *user_data)


/**
 * \brief Load journal function for FRITZ!OS >= 5.50
 * \param profile router info structure
 * \param data_ptr data pointer to optional store journal to
 * \return error code
 */
gboolean fritzbox_load_journal_05_50(struct router_icl *ri, gchar **data_ptr)
{
	SoupMessage *msg;
  printf("hier fritzbox_load_journal_05_05\n");

	/* Login to box */
	if (!fritzbox_login(ri)/*router_login(profile)*/) {
		fdebug("Login failed");
		return FALSE;
	}

	/* Create GET request */
	gchar *url = g_strdup_printf("http://%s/fon_num/foncalls_list.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            "csv", "",
	                            NULL);
	g_free(url);

	/* Queue message to session */
  #ifdef asynch
  GMainLoop *loop= g_main_loop_new(NULL, FALSE);
  soup_session_queue_message(soup_session, msg, fritzbox_journal_05_50_cb, ri);
  g_main_loop_run (loop);
  #else
		soup_session_send_message (soup_session, msg);
    fritzbox_journal_05_50_cb(soup_session,msg,ri);
    printf("juhuuu\n");
  #endif

  printf("Ende fritzbox_load_journal_05_05\n");
	return TRUE;
}

/**
 * \brief Journal callback function (parse data and emit "journal-process"/"journal-loaded" signals, logout)
 * \param session soup session
 * \param msg soup message
 * \param user_data poiner to profile structure
 */
void fritzbox_journal_04_74_cb(SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	GSList *journal = NULL;
	//struct profile *profile = user_data;
  struct router_icl *ri = (router_icl*)user_data;

	/* Parse journal */
	journal = csv_parse_fritzbox_journal_data(journal, msg->response_body->data,ri);

	/* Load and add faxbox */
	journal = fritzbox_load_faxbox(ri,journal);

	/* Load and add voicebox */
	journal = fritzbox_load_voicebox(ri,journal);

	/* Load fax reports */
	journal = router_load_fax_reports(ri, journal);

	/* Load voice records */
	journal = router_load_voice_records(ri, journal);

	router_process_journal(journal,ri);

	/* Logout */
	fritzbox_logout(ri, FALSE);
}


/**
 * \brief Load journal function for FRITZ!OS >= 4.74 && < 5.50
 * \param profile profile info structure
 * \param data_ptr data pointer to optional store journal to
 * \return error code
 */
gboolean fritzbox_load_journal_04_74(struct router_icl *ri, gchar **data_ptr)
{
	SoupMessage *msg;
	gchar *url;

	/* Login to box */
	if (!fritzbox_login(ri)/*router_login(profile)*/) {
		fdebug("Login failed");
		return FALSE;
	}

	/* Create POST request */
	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "getpage", "../html/de/menus/menu2.html",
	                            "var:lang", ri->lang,
	                            "var:pagename", "foncalls",
	                            "var:menu", "fon",
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		fdebug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	g_object_unref(msg);

	/* Create POST request */
	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "getpage", "../html/de/FRITZ!Box_Anrufliste.csv",
	                            "sid", ri->session_id,
	                            NULL);
	g_free(url);

	/* Queue message to session */
	soup_session_queue_message(soup_session, msg, fritzbox_journal_04_74_cb, ri);

	return TRUE;
}


/**
 * \brief Main load journal function (big switch for each supported router)
 * \param profile profile info structure
 * \param data_ptr data pointer to optional store journal to
 * \return error code
 */
gboolean fritzbox_load_journal(struct router_icl *ri, gchar **data_ptr)
{
  printf("hier fritzbox_load_journal\n");
	gboolean ret = FALSE;

	if (FIRMWARE_IS(5, 50)) {
		ret = fritzbox_load_journal_05_50(ri, data_ptr);
	} else if (FIRMWARE_IS(4, 0)) {
		ret = fritzbox_load_journal_04_74(ri, data_ptr);
	}

	return ret;
}

struct address_book {
	gchar *name;
	gchar *(*get_active_book_name)(void);
	GSList *(*get_contacts)(void);
	gboolean (*reload_contacts)(router_icl *ri);
	gboolean (*remove_contact)(router_icl *ri, struct contact *contact);
	gboolean (*save_contact)(router_icl *ri, struct contact *contact);
};

gchar *fritzfon_get_active_book_name(void)
{
	return g_strdup("FritzFon");
}

static struct contacts *contacts = NULL;
GSList *fritzfon_get_contacts(void)
{
	GSList *list = (GSList*)contacts;

	return list;
}

typedef enum {
	XMLNODE_TYPE_TAG,
	XMLNODE_TYPE_ATTRIB,
	XMLNODE_TYPE_DATA
} xml_node_type;

typedef struct xml_node {
	gchar *name;
	gchar *xml_ns;
	xml_node_type type;
	gchar *data;
	size_t data_size;
	struct xml_node *parent;
	struct xml_node *child;
	struct xml_node *last_child;
	struct xml_node *next;
	gchar *prefix;
	GHashTable *namespace_map;
} xmlnode;

/** xmlnode parser data structure */
struct _xmlnode_parser_data {
	xmlnode *current;
	gboolean error;
};

/**
 * \brief Create new xml node
 * \param name node name
 * \param type node type
 * \return new node pointer
 */
xmlnode *new_node(const gchar *name, xml_node_type type)
{
	xmlnode *node = g_new0(xmlnode, 1);

	node->name = g_strdup(name);
	node->type = type;

	return node;
}

/**
 * \brief Insert child into parent node
 * \param parent parent node
 * \param child child node
 */
void xmlnode_insert_child(xmlnode *parent, xmlnode *child)
{
	g_return_if_fail(parent != NULL);
	g_return_if_fail(child != NULL);

	child->parent = parent;

	if (parent->last_child) {
		parent->last_child->next = child;
	} else {
		parent->child = child;
	}

	parent->last_child = child;
}

/**
 * \brief Insert data into xmlnode
 * \param node xml node
 * \param data data pointer
 * \param size size of data
 */
void xmlnode_insert_data(xmlnode *node, const gchar *data, gssize size)
{
	xmlnode *child;
	gsize real_size;

	g_return_if_fail(node != NULL);
	g_return_if_fail(data != NULL);
	g_return_if_fail(size != 0);

	if (size == -1) {
		real_size = strlen(data);
	} else {
		real_size = size;
	}

	child = new_node(NULL, XMLNODE_TYPE_DATA);

	child->data = (gchar*)g_memdup(data, real_size);
	child->data_size = real_size;

	xmlnode_insert_child(node, child);
}

/**
 * \brief Parser error
 * \param user_data xmlnode parser data
 * \param msg error message
 */
static void xmlnode_parser_error_libxml(void *user_data, const gchar *msg, ...)
{
	struct _xmlnode_parser_data *xpd = (_xmlnode_parser_data*)user_data;
	gchar err_msg[2048];
	va_list args;

	xpd->error = TRUE;

	va_start(args, msg);
	vsnprintf(err_msg, sizeof(err_msg), msg, args);
	va_end(args);

	fdebug("Error parsing xml file: %s", err_msg);
}


/**
 * \brief Parser: Element text
 * \param user_data xmlnode parser data
 * \param text text element
 * \param text_len text length
 */
static void xmlnode_parser_element_text_libxml(void *user_data, const xmlChar *text, gint text_len)
{
	struct _xmlnode_parser_data *xpd = (_xmlnode_parser_data*)user_data;

	if (!xpd->current || xpd->error) {
		return;
	}

	if (!text || !text_len) {
		return;
	}

	xmlnode_insert_data(xpd->current, (const gchar *) text, text_len);
}


/**
 * \brief Create new child node
 * \param parent parent node
 * \param name node name
 * \return new node pointer or NULL on error
 */
xmlnode *xmlnode_new_child(xmlnode *parent, const gchar *name)
{
	xmlnode *node;

	g_return_val_if_fail(parent != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	node = new_node(name, XMLNODE_TYPE_TAG);

	xmlnode_insert_child(parent, node);

	return node;
}

/**
 * \brief Create a new tag node
 * \param name node name
 * \return new node pointer or NULL on error
 */
xmlnode *xmlnode_new(const gchar *name)
{
	g_return_val_if_fail(name != NULL, NULL);

	return new_node(name, XMLNODE_TYPE_TAG);
}

/**
 * \brief Set namespace
 * \param node xml node
 * \param xml_ns xml namespace
 */
void xmlnode_set_namespace(xmlnode *node, const gchar *xml_ns)
{
	g_return_if_fail(node != NULL);

	g_free(node->xml_ns);
	node->xml_ns = g_strdup(xml_ns);
}

/**
 * \brief Set prefix
 * \param node xml node
 * \param prefix prefix
 */
static void xmlnode_set_prefix(xmlnode *node, const gchar *prefix)
{
	g_return_if_fail(node != NULL);

	g_free(node->prefix);
	node->prefix = g_strdup(prefix);
}

/**
 * \brief Unescape html text
 * \param html html text
 * \return unescaped text
 */
static gchar *unescape_html(const gchar *html)
{
	if (html != NULL) {
		const gchar *c = html;
		GString *ret = g_string_new("");

		while (*c) {
			if (!strncmp(c, "<br>", 4)) {
				ret = g_string_append_c(ret, '\n');
				c += 4;
			} else {
				ret = g_string_append_c(ret, *c);
				c++;
			}
		}

		return g_string_free(ret, FALSE);
	}

	return NULL;
}

/**
 * \brief Set attribute with prefix
 * \param node xml node
 * \param attr attribute
 * \param prefix prefix
 * \param value value
 */
static void xmlnode_set_attrib_with_prefix(xmlnode *node, const gchar *attr, const gchar *prefix, const gchar *value)
{
	xmlnode *attrib_node;

	g_return_if_fail(node != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(value != NULL);

	attrib_node = new_node(attr, XMLNODE_TYPE_ATTRIB);

	attrib_node->data = g_strdup(value);
	attrib_node->prefix = g_strdup(prefix);

	xmlnode_insert_child(node, attrib_node);
}


/**
 * \brief Free node
 * \param node node to free
 */
void xmlnode_free(xmlnode *node)
{
	xmlnode *x, *y;

	g_return_if_fail(node != NULL);

	if (node->parent != NULL) {
		if (node->parent->child == node) {
			node->parent->child = node->next;
			if (node->parent->last_child == node) {
				node->parent->last_child = node->next;
			}
		} else {
			xmlnode *prev = node->parent->child;
			while (prev && prev->next != node) {
				prev = prev->next;
			}

			if (prev) {
				prev->next = node->next;
				if (node->parent->last_child == node) {
					node->parent->last_child = prev;
				}
			}
		}
	}

	x = node->child;
	while (x) {
		y = x->next;
		xmlnode_free(x);
		x = y;
	}

	g_free(node->name);
	g_free(node->data);
	g_free(node->xml_ns);
	g_free(node->prefix);

	if (node->namespace_map) {
		g_hash_table_destroy(node->namespace_map);
	}

	g_free(node);
}

/**
 * \brief Remove attribute from node
 * \param node node pointer
 * \param attr attribute name
 */
static void xmlnode_remove_attrib(xmlnode *node, const gchar *attr)
{
	xmlnode *attr_node, *sibling = NULL;

	g_return_if_fail(node != NULL);
	g_return_if_fail(attr != NULL);

	for (attr_node = node->child; attr_node != NULL; attr_node = attr_node->next) {
		if (attr_node->type == XMLNODE_TYPE_ATTRIB && !strcmp(attr_node->name, attr)) {
			if (sibling == NULL) {
				node->child = attr_node->next;
			} else {
				sibling->next = attr_node->next;
			}

			if (node->last_child == attr_node) {
				node->last_child = sibling;
			}
			xmlnode_free(attr_node);

			return;
		}
		sibling = attr_node;
	}
}

/**
 * \brief Set attribute for node
 * \param node node pointer
 * \param attr attribute name
 * \param value value to set
 */
void xmlnode_set_attrib(xmlnode *node, const gchar *attr, const gchar *value)
{
	xmlnode *attrib_node;

	g_return_if_fail(node != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(value != NULL);

	xmlnode_remove_attrib(node, attr);

	attrib_node = new_node(attr, XMLNODE_TYPE_ATTRIB);

	attrib_node->data = g_strdup(value);

	xmlnode_insert_child(node, attrib_node);
}


/**
 * \brief Parser: Element end
 * \param user_data xmlnode parser data
 * \param element_name element name
 * \param prefix prefix
 * \param xml_ns xml namespace
 */
static void xmlnode_parser_element_end_libxml(void *user_data, const xmlChar *element_name, const xmlChar *prefix, const xmlChar *xml_ns)
{
	struct _xmlnode_parser_data *xpd = (_xmlnode_parser_data*)user_data;

	if (!element_name || !xpd->current || xpd->error) {
		return;
	}

	if (xpd->current->parent) {
		if (!xmlStrcmp((xmlChar *) xpd->current->name, element_name)) {
			xpd->current = xpd->current->parent;
		}
	}
}


/**
 * \brief Parser: Element start
 * \param user_data xmlnode parser data
 * \param element_name element name
 * \param prefix prefix
 * \param xml_ns xml namespace
 * \param nb_namespaces number of namespaces
 * \param namespaces pointer to xml namespaces
 * \param nb_attributes number of attributes
 * \param nb_defaulted number of defaulted
 * \param attributes pointer to xml attributes
 */
static void xmlnode_parser_element_start_libxml(void *user_data, const xmlChar *element_name, const xmlChar *prefix,
        const xmlChar *xml_ns, gint nb_namespaces, const xmlChar **namespaces, gint nb_attributes, gint nb_defaulted,
        const xmlChar **attributes)
{
	struct _xmlnode_parser_data *xpd = (_xmlnode_parser_data*)user_data;
	xmlnode *node;
	gint i, j;

	if (!element_name || xpd->error) {
		return;
	}

	if (xpd->current) {
		node = xmlnode_new_child(xpd->current, (const gchar *) element_name);
	} else {
		node = xmlnode_new((const gchar *) element_name);
	}

	xmlnode_set_namespace(node, (const gchar *) xml_ns);
	xmlnode_set_prefix(node, (const gchar *) prefix);

	if (nb_namespaces != 0) {
		node->namespace_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

		for (i = 0, j = 0; i < nb_namespaces; i++, j += 2) {
			const gchar *key = (const gchar *) namespaces[j];
			const gchar *val = (const gchar *) namespaces[j + 1];

			g_hash_table_insert(node->namespace_map, g_strdup(key ? key : ""), g_strdup(val ? val : ""));
		}
	}

	for (i = 0; i < nb_attributes * 5; i += 5) {
		const gchar *prefix = (const gchar *) attributes[i + 1];
		gchar *txt;
		gint attrib_len = attributes[i + 4] - attributes[i + 3];
		gchar *attrib = (gchar*)g_malloc(attrib_len + 1);

		memcpy(attrib, attributes[i + 3], attrib_len);
		attrib[attrib_len] = '\0';
		txt = attrib;
		attrib = unescape_html(txt);
		g_free(txt);

		if (prefix && *prefix) {
			xmlnode_set_attrib_with_prefix(node, (const gchar *) attributes[i], prefix, attrib);
		} else {
			xmlnode_set_attrib(node, (const gchar *) attributes[i], attrib);
		}
		g_free(attrib);
	}

	xpd->current = node;
}


/** xmlnode parser libxml */
static xmlSAXHandler xml_node_parser_libxml = {
	/* internalSubset */
	NULL,
	/* isStandalone */
	NULL,
	/* hasInternalSubset */
	NULL,
	/* hasExternalSubset */
	NULL,
	/* resolveEntity */
	NULL,
	/* getEntity */
	NULL,
	/* entityDecl */
	NULL,
	/* notationDecl */
	NULL,
	/* attributeDecl */
	NULL,
	/* elementDecl */
	NULL,
	/* unparsedEntityDecl */
	NULL,
	/* setDocumentLocator */
	NULL,
	/* startDocument */
	NULL,
	/* endDocument */
	NULL,
	/* startElement */
	NULL,
	/* endElement */
	NULL,
	/* reference */
	NULL,
	/* characters */
	xmlnode_parser_element_text_libxml,
	/* ignorableWhitespace */
	NULL,
	/* processingInstruction */
	NULL,
	/* comment */
	NULL,
	/* warning */
	NULL,
	/* error */
	xmlnode_parser_error_libxml,
	/* fatalError */
	NULL,
	/* getParameterEntity */
	NULL,
	/* cdataBlock */
	NULL,
	/* externalSubset */
	NULL,
	/* initialized */
	XML_SAX2_MAGIC,
	/* _private */
	NULL,
	/* startElementNs */
	xmlnode_parser_element_start_libxml,
	/* endElementNs */
	xmlnode_parser_element_end_libxml,
	/* serror */
	NULL,
};


/**
 * \brief Create xmlnode from string
 * \param str string
 * \param size size of string
 * \return new xml node
 */
xmlnode *xmlnode_from_str(const gchar *str, gssize size)
{
	struct _xmlnode_parser_data *xpd;
	xmlnode *ret;
	gsize real_size;

	g_return_val_if_fail(str != NULL, NULL);

	real_size = size < 0 ? strlen(str) : size;
	xpd = g_new0(struct _xmlnode_parser_data, 1);

	if (xmlSAXUserParseMemory(&xml_node_parser_libxml, xpd, str, real_size) < 0) {
		while (xpd->current && xpd->current->parent) {
			xpd->current = xpd->current->parent;
		}

		if (xpd->current) {
			xmlnode_free(xpd->current);
		}
		xpd->current = NULL;
	}
	ret = xpd->current;

	if (xpd->error) {
		ret = NULL;

		if (xpd->current) {
			xmlnode_free(xpd->current);
		}
	}

	g_free(xpd);

	return ret;
}


/**
 * \brief Get namespace
 * \param node xml node
 * \return namespace
 */
const gchar *xmlnode_get_namespace(xmlnode *node)
{
	g_return_val_if_fail(node != NULL, NULL);

	return node->xml_ns;
}

xmlnode *xmlnode_get_child(const xmlnode *parent, const gchar *name);

/**
 * \brief Get child with namespace
 * \param parent parent xml node
 * \param name child name
 * \param ns namespace
 * \return chuld xmlnode
 */
xmlnode *xmlnode_get_child_with_namespace(const xmlnode *parent, const gchar *name, const gchar *ns)
{
	xmlnode *x, *ret = NULL;
	gchar **names;
	gchar *parent_name, *child_name;

	g_return_val_if_fail(parent != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	names = g_strsplit(name, "/", 2);
	parent_name = names[0];
	child_name = names[1];

	for (x = parent->child; x; x = x->next) {
		const gchar *xml_ns = NULL;

		if (ns != NULL) {
			xml_ns = xmlnode_get_namespace(x);
		}

		if (x->type == XMLNODE_TYPE_TAG && name && !strcmp(parent_name, x->name) && (!ns || (xml_ns && !strcmp(ns, xml_ns)))) {
			ret = x;
			break;
		}
	}

	if (child_name && ret) {
		ret = xmlnode_get_child(ret, child_name);
	}

	g_strfreev(names);

	return ret;
}

xmlnode *xmlnode_get_child(const xmlnode *parent, const gchar *name);

/**
 * \brief Get xml node child
 * \param parent xml node parent
 * \param name child name
 * \return child xmlnode
 */
xmlnode *xmlnode_get_child(const xmlnode *parent, const gchar *name)
{
	return xmlnode_get_child_with_namespace(parent, name, NULL);
}


/**
 * \brief Get next twin from xml node
 * \param node xml node
 * \return next xml node twin
 */
xmlnode *xmlnode_get_next_twin(xmlnode *node)
{
	xmlnode *sibling;
	const gchar *ns = xmlnode_get_namespace(node);

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(node->type == XMLNODE_TYPE_TAG, NULL);

	for (sibling = node->next; sibling; sibling = sibling->next) {
		const gchar *xml_ns = NULL;

		if (ns != NULL) {
			xml_ns = xmlnode_get_namespace(sibling);
		}

		if (sibling->type == XMLNODE_TYPE_TAG && !strcmp(node->name, sibling->name) && (!ns || (xml_ns && !strcmp(ns, xml_ns)))) {
			return sibling;
		}
	}

	return NULL;
}

struct fritzfon_priv {
	gchar *unique_id;
	gchar *image_url;
	GSList *nodes;
};


/**
 * \brief Get data from xmlnode
 * \param node xml node
 * \return xmlnode data
 */
gchar *xmlnode_get_data(xmlnode *node)
{
	GString *str = NULL;
	xmlnode *c;

	g_return_val_if_fail(node != NULL, NULL);

	for (c = node->child; c; c = c->next) {
		if (c->type == XMLNODE_TYPE_DATA) {
			if (!str) {
				str = g_string_new_len(c->data, c->data_size);
			} else {
				str = g_string_append_len(str, c->data, c->data_size);
			}
		}
	}

	if (str == NULL) {
		return NULL;
	}

	return g_string_free(str, FALSE);
}

static void parse_person(router_icl* ri,struct contact *contact, xmlnode *person)
{
	xmlnode *name;
	xmlnode *image;
	gchar *image_ptr;
	struct fritzfon_priv *priv = (fritzfon_priv*)contact->priv;

	/* Get real name entry */
	name = xmlnode_get_child(person, "realName");
	contact->name = name ? xmlnode_get_data(name) : g_strdup("");

	/* Get image */
	image = xmlnode_get_child(person, "imageURL");
	if (image != NULL) {
		image_ptr = xmlnode_get_data(image);
		priv->image_url = image_ptr;
		if (image_ptr != NULL) {
			/* file:///var/InternerSpeicher/FRITZ/fonpix/946684999-0.jpg */
			if (!strncmp(image_ptr, "file://", 7) && strlen(image_ptr) > 28) {
				// struct profile *profile = profile_get_active();
				gchar *url = strstr(image_ptr, "/ftp/");
				gsize len;
				guchar *buffer;
				struct ftp *client;
				GdkPixbufLoader *loader;

				if (!url) {
					url = strstr(image_ptr, "/FRITZ/");
				} else {
					url += 5;
				}

				//client = ftp_init(router_get_host(profile_get_active()));
        client = ftp_init(ri->host);
        //ftp_login(client, router_get_ftp_user(profile), router_get_ftp_password(profile));
        ftp_login(client, ri->ftpusr, ri->ftppwd);
				ftp_passive(client);
				buffer = (guchar *) ftp_get_file(client, url, &len);
				ftp_shutdown(client);

				loader = gdk_pixbuf_loader_new();
				if (gdk_pixbuf_loader_write(loader, buffer, len, NULL)) {
					contact->image = gdk_pixbuf_loader_get_pixbuf(loader);
					contact->image_len = len;
				}
				gdk_pixbuf_loader_close(loader, NULL);
			}
		}
	}
}

/**
 * \brief Get attribute from node
 * \param node xml node structure
 * \param attr attribute name
 * \return attribute data
 */
const gchar *xmlnode_get_attrib(xmlnode *node, const gchar *attr)
{
	xmlnode *x;

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(attr != NULL, NULL);

	for (x = node->child; x != NULL; x = x->next) {
		if (x->type == XMLNODE_TYPE_ATTRIB && strcmp(attr, x->name) == 0) {
			return x->data;
		}
	}

	return NULL;
}

/*
 * \brief Get router country code
 * \param profile router information structure
 * \return country code
 */
gchar *router_get_country_code(router_icl *ri/*struct profile *profile*/)
{
//	if (!profile || !profile->settings) { return NULL; }
//	return g_settings_get_string(profile->settings, "country-code");
  return g_strdup(ri->lkz);
}

/** Call-by-call number table */
struct call_by_call_entry call_by_call_table[] = {
	{(gchar*)"49", (gchar*)"0100", 6},
	{(gchar*)"49", (gchar*)"010", 5},
	{(gchar*)"31", (gchar*)"16", 4},
	{ (gchar*)"", (gchar*)"", 0},
};

/**
 * call_by_call_prefix_length:
 * @number: input number string
 *
 * Get call-by-call prefix length
 *
 * Returns: length of call-by-call prefix
 */
gint call_by_call_prefix_length(router_icl *ri, const gchar *number)
{
	gchar *my_country_code = router_get_country_code(ri);
	struct call_by_call_entry *entry;

	if (EMPTY_STRING(my_country_code)) {
		g_free(my_country_code);
		return 0;
	}

	for (entry = call_by_call_table; strlen(entry->country_code); entry++) {
		if (!strcmp(my_country_code, entry->country_code) && !strncmp(number, entry->prefix, strlen(entry->prefix))) {
			g_free(my_country_code);
			return entry->prefix_length;
		}
	}

	g_free(my_country_code);

	return 0;
}

/**
 * \brief Convenient function to retrieve standardized number without call by call prefix
 * \param number input phone number
 * \param country_code_prefix whether we want a international or national phone number format
 * \return canonized and formatted phone number
 */
gchar *call_full_number(router_icl *ri,const gchar *number, gboolean country_code_prefix)
{
	if (EMPTY_STRING(number)) {
		return NULL;
	}

	/* Skip numbers with leading '*' or '#' */
	if (number[0] == '*' || number[0] == '#') {
		return g_strdup(number);
	}

	/* Remove call-by-call (carrier preselect) prefix */
	number += call_by_call_prefix_length(ri,number);

	/* Check if it is an international number */
	if (!strncmp(number, "00", 2)) {
		gchar *out;
		gchar *my_country_code;

		if (country_code_prefix) {
			return g_strdup(number);
		}

		my_country_code = router_get_country_code(ri);
		if (!strncmp(number + 2, my_country_code, strlen(my_country_code)))  {
			out = g_strdup_printf("0%s", number + 4);
		} else {
			out = g_strdup(number);
		}

		return out;
	}

	return call_format_number(ri/*profile_get_active()*/, number, country_code_prefix ? NUMBER_FORMAT_INTERNATIONAL : NUMBER_FORMAT_NATIONAL);
}

static void parse_telephony(router_icl *ri,struct contact *contact, xmlnode *telephony)
{
	xmlnode *child;
	gchar *number = NULL;

	/* Check for numbers */
	for (child = xmlnode_get_child(telephony, "number"); child != NULL; child = xmlnode_get_next_twin(child)) {
		const gchar *type;

		type = xmlnode_get_attrib(child, "type");
		if (type == NULL) {
			continue;
		}

		number = xmlnode_get_data(child);
		if (!EMPTY_STRING(number)) {
			struct phone_number *phone_number;

			phone_number = g_slice_new(struct phone_number);
			if (strcmp(type, "mobile") == 0) {
				phone_number->type = PHONE_NUMBER_MOBILE;
			} else if (strcmp(type, "home") == 0) {
				phone_number->type = PHONE_NUMBER_HOME;
			} else if (strcmp(type, "work") == 0) {
				phone_number->type = PHONE_NUMBER_WORK;
			} else if (strcmp(type, "fax_work") == 0) {
				phone_number->type = PHONE_NUMBER_FAX_WORK;
			} else if (strcmp(type, "fax_home") == 0) {
				phone_number->type = PHONE_NUMBER_FAX_HOME;
			} else if (strcmp(type, "pager") == 0) {
				phone_number->type = PHONE_NUMBER_PAGER;
			} else {
				phone_number->type = (phone_number_type)-1;
				fdebug("Unhandled phone number type: '%s'", type);
			}
			phone_number->number = call_full_number(ri,number, FALSE);
			contact->numbers = g_slist_prepend(contact->numbers, phone_number);
		}

		g_free(number);
	}
}

/**
 * \brief Insert key/value into hash-table
 * \param key key type
 * \param value value type
 * \param user_data pointer to hash table
 */
static void xmlnode_copy_foreach_ns(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable *ret = (GHashTable *)user_data;
	g_hash_table_insert(ret, g_strdup((const gchar*)key), g_strdup((const gchar*)value));
}

/**
 * \brief Make a copy of a given xmlnode
 * \param src source xml node
 * \return new xml node
 */
xmlnode *xmlnode_copy(const xmlnode *src)
{
	xmlnode *ret;
	xmlnode *child;
	xmlnode *sibling = NULL;

	g_return_val_if_fail(src != NULL, NULL);

	ret = new_node(src->name, src->type);
	ret->xml_ns = g_strdup(src->xml_ns);

	if (src->data) {
		if (src->data_size) {
			ret->data = (gchar*)g_memdup(src->data, src->data_size);
			ret->data_size = src->data_size;
		} else {
			ret->data = g_strdup(src->data);
		}
	}

	ret->prefix = g_strdup(src->prefix);

	if (src->namespace_map) {
		ret->namespace_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		g_hash_table_foreach(src->namespace_map, xmlnode_copy_foreach_ns, ret->namespace_map);
	}

	for (child = src->child; child; child = child->next) {
		if (sibling) {
			sibling->next = xmlnode_copy(child);
			sibling = sibling->next;
		} else {
			ret->child = xmlnode_copy(child);
			sibling = ret->child;
		}
		sibling->parent = ret;
	}

	ret->last_child = sibling;

	return ret;
}

gint contact_name_compare(gconstpointer a, gconstpointer b)
{
	struct contact *contact_a = (struct contact *)a;
	struct contact *contact_b = (struct contact *)b;

	return strcasecmp(contact_a->name, contact_b->name);
}

static void contact_add(router_icl *ri, xmlnode *node, gint count)
{
	xmlnode *tmp;
	struct contact *contact;
	struct fritzfon_priv *priv;

	contact = g_slice_new0(struct contact);
	priv = g_slice_new0(struct fritzfon_priv);
	contact->priv = priv;

	for (tmp = node->child; tmp != NULL; tmp = tmp->next) {
		if (tmp->name == NULL) {
			continue;
		}

		if (!strcmp(tmp->name, "person")) {
			parse_person(ri,contact, tmp);
		} else if (!strcmp(tmp->name, "telephony")) {
			parse_telephony(ri,contact, tmp);
		} else if (!strcmp(tmp->name, "uniqueid")) {
			priv->unique_id = xmlnode_get_data(tmp);
		} else if (!strcmp(tmp->name, "mod_time")) {
			/* empty */
		} else {
			/* Unhandled node, save it */
			priv->nodes = g_slist_prepend(priv->nodes, xmlnode_copy(tmp));
		}
	}

	contacts = (struct contacts*)g_slist_insert_sorted((GSList*)contacts, contact, contact_name_compare);
}

static void phonebook_add(router_icl *ri, xmlnode *node)
{
	xmlnode *child;
	gint count = 0;

	for (child = xmlnode_get_child(node, "contact"); child != NULL; child = xmlnode_get_next_twin(child)) {
		contact_add(ri, child, count++);
	}
}



// static GSettings *fritzfon_settings = NULL;
static xmlnode *master_node = NULL;
static gint fritzfon_read_book(struct router_icl *ri)
{
	gchar uri[1024];
	xmlnode *node = NULL;
	xmlnode *child;
	gchar *owner;
	gchar *name;

	contacts = NULL;

	if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return -1;
	}

	owner = g_strdup("0"); // g_settings_get_string(fritzfon_settings, "book-owner");
	name = g_strdup("Telefonbuch"); // g_settings_get_string(fritzfon_settings, "book-name");

	snprintf(uri, sizeof(uri), "http://%s/cgi-bin/firmwarecfg", ri->host/*router_get_host(profile)*/);

	SoupMultipart *multipart = soup_multipart_new(SOUP_FORM_MIME_TYPE_MULTIPART);
	soup_multipart_append_form_string(multipart, "sid", ri->session_id);
	soup_multipart_append_form_string(multipart, "PhonebookId", owner);
	soup_multipart_append_form_string(multipart, "PhonebookExportName", name);
	soup_multipart_append_form_string(multipart, "PhonebookExport", "1");
	SoupMessage *msg = soup_form_request_new_from_multipart(uri, multipart);

	soup_session_send_message(soup_session, msg);

	g_free(owner);
	g_free(name);

	if (msg->status_code != 200) {
		g_warning("Could not get firmware file");
		g_object_unref(msg);
		return FALSE;
	}

	const gchar *data = msg->response_body->data;
	gint read = msg->response_body->length;

	g_return_val_if_fail(data != NULL, -2);
#if FRITZFON_DEBUG
	if (read > 0) {
		log_save_data("test-in.xml", data, read);
	}
#endif

	node = xmlnode_from_str(data, read);
	if (node == NULL) {
		g_object_unref(msg);
		return -1;
	}

	master_node = node;

	for (child = xmlnode_get_child(node, "phonebook"); child != NULL; child = xmlnode_get_next_twin(child)) {
		phonebook_add(ri, child);
	}

	g_object_unref(msg);

	//router_logout(profile);

	return 0;
}

gboolean fritzfon_reload_contacts(struct router_icl *ri)
{
	return fritzfon_read_book(ri) == 0;
}


/**
 * \brief Convert person structure to xml node
 * \param contact person structure
 * \return xml node
 */
static xmlnode *contact_to_xmlnode(struct contact *contact)
{
	xmlnode *node;
	xmlnode *contact_node;
	xmlnode *realname_node;
	xmlnode *image_node;
	xmlnode *telephony_node;
	xmlnode *tmp_node;
	GSList *list;
	gchar *tmp;
	struct fritzfon_priv *priv = (struct fritzfon_priv*)contact->priv;

	/* Main contact entry */
	node = xmlnode_new("contact");

	/* Person */
	contact_node = xmlnode_new("person");

	realname_node = xmlnode_new("realName");
	xmlnode_insert_data(realname_node, contact->name, -1);
	xmlnode_insert_child(contact_node, realname_node);

	/* ImageURL */
	if (priv && priv->image_url) {
		image_node = xmlnode_new("imageURL");
		xmlnode_insert_data(image_node, priv->image_url, -1);
		xmlnode_insert_child(contact_node, image_node);
	}

	/* Insert person to main node */
	xmlnode_insert_child(node, contact_node);

	/* Telephony */
	if (contact->numbers) {
		gboolean first = TRUE;
		gint id = 0;
		gchar *tmp = g_strdup_printf("%d", g_slist_length(contact->numbers));

		telephony_node = xmlnode_new("telephony");
		xmlnode_set_attrib(telephony_node, "nid", tmp);
		g_free(tmp);

		for (list = contact->numbers; list != NULL; list = list->next) {
			struct phone_number *number = (struct phone_number*)list->data;
			xmlnode *number_node;

			number_node = xmlnode_new("number");

			switch (number->type) {
			case PHONE_NUMBER_HOME:
				xmlnode_set_attrib(number_node, "type", "home");
				break;
			case PHONE_NUMBER_WORK:
				xmlnode_set_attrib(number_node, "type", "work");
				break;
			case PHONE_NUMBER_MOBILE:
				xmlnode_set_attrib(number_node, "type", "mobile");
				break;
			case PHONE_NUMBER_FAX_WORK:
				xmlnode_set_attrib(number_node, "type", "fax_work");
				break;
			case PHONE_NUMBER_FAX_HOME:
				xmlnode_set_attrib(number_node, "type", "fax_home");
				break;
			default:
				continue;
			}

			if (first) {
				/* For the meantime set priority to 1 */
				xmlnode_set_attrib(number_node, "prio", "1");
				first = FALSE;
			}

			tmp = g_strdup_printf("%d", id++);
			xmlnode_set_attrib(number_node, "id", tmp);
			g_free(tmp);

			xmlnode_insert_data(number_node, number->number, -1);
			xmlnode_insert_child(telephony_node, number_node);
		}
		xmlnode_insert_child(node, telephony_node);
	}

	tmp_node = xmlnode_new("mod_time");
	tmp = g_strdup_printf("%u", (unsigned)time(NULL));
	xmlnode_insert_data(tmp_node, tmp, -1);
	xmlnode_insert_child(node, tmp_node);
	g_free(tmp);

	tmp_node = xmlnode_new("uniqueid");
	if (priv && priv->unique_id) {
		xmlnode_insert_data(tmp_node, priv->unique_id, -1);
	}
	xmlnode_insert_child(node, tmp_node);

	if (priv) {
		for (list = priv->nodes; list != NULL; list = list->next) {
			xmlnode *priv_node = (xmlnode*)list->data;
			xmlnode_insert_child(node, priv_node);
		}
	}

	return node;
}

/**
 * \brief Convert phonebooks to xml node
 * \return xml node
 */
xmlnode *phonebook_to_xmlnode(void)
{
	xmlnode *node;
	xmlnode *child;
	xmlnode *book;
	GSList *list;

	/* Create general phonebooks node */
	node = xmlnode_new("phonebooks");

	/* Currently we only support one phonebook, TODO */
	book = xmlnode_new("phonebook");
	xmlnode_set_attrib(book, "owner", g_strdup("0")/*g_settings_get_string(fritzfon_settings, "book-owner")*/);
	xmlnode_set_attrib(book, "name", g_strdup("Telefonbuch")/*g_settings_get_string(fritzfon_settings, "book-name")*/);
	xmlnode_insert_child(node, book);

	/* Loop through persons list and add only non-deleted entries */
	for (list = (GSList*)contacts; list != NULL; list = list->next) {
		struct contact *contact = (struct contact*)list->data;

		/* Convert each contact and add it to current phone book */
		child = contact_to_xmlnode(contact);
		xmlnode_insert_child(book, child);
	}

	return node;
}


/**
 * \brief Get node prefix
 * \param node node pointer
 * \return node prefix
 */
static const gchar *xmlnode_get_prefix(xmlnode *node)
{
	g_return_val_if_fail(node != NULL, NULL);

	return node->prefix;
}

/**
 * \brief Convert node to string
 * \param key key name
 * \param value value
 * \param buf buffer to print to
 */
static void xmlnode_to_str_foreach_append_ns(const gchar *key, const gchar *value, GString *buf)
{
	if (*key) {
		g_string_append_printf(buf, " xmlns:%s='%s'", key, value);
	} else {
		g_string_append_printf(buf, " xmlns='%s'", value);
	}
}

/**
 * \brief Helps with converting node to string
 * \param node node to convert
 * \param len pointer for len saving
 * \param formatting format text?
 * \param depth depth
 * \return string data or NULL on error
 */
static gchar *xmlnode_to_str_helper(xmlnode *node, gint *len, gboolean formatting, gint depth)
{
	GString *text = g_string_new("");
	const gchar *prefix;
	xmlnode *c;
	gchar *node_name, *esc, *esc2, *tab = NULL;
	gboolean need_end = FALSE, pretty = formatting;

	g_return_val_if_fail(node != NULL, NULL);

	if (pretty && depth) {
		tab = g_strnfill(depth, '\t');
		text = g_string_append(text, tab);
	}

	node_name = g_markup_escape_text(node->name, -1);
	prefix = xmlnode_get_prefix(node);

	if (prefix) {
		g_string_append_printf(text, "<%s:%s", prefix, node_name);
	} else {
		g_string_append_printf(text, "<%s", node_name);
	}

	if (node->namespace_map) {
		g_hash_table_foreach(node->namespace_map, (GHFunc) xmlnode_to_str_foreach_append_ns, text);
	} else if (node->xml_ns) {
		if (!node->parent || !node->parent->xml_ns || strcmp(node->xml_ns, node->parent->xml_ns)) {
			gchar *xml_ns = g_markup_escape_text(node->xml_ns, -1);

			g_string_append_printf(text, " xmlns='%s'", xml_ns);
			g_free(xml_ns);
		}
	}

	for (c = node->child; c != NULL; c = c->next) {
		if (c->type == XMLNODE_TYPE_ATTRIB) {
			const gchar *a_prefix = xmlnode_get_prefix(c);

			esc = g_markup_escape_text(c->name, -1);
			esc2 = g_markup_escape_text(c->data, -1);

			if (a_prefix) {
				g_string_append_printf(text, " %s:%s='%s'", a_prefix, esc, esc2);
			} else {
				g_string_append_printf(text, " %s='%s'", esc, esc2);
			}

			g_free(esc);
			g_free(esc2);
		} else if (c->type == XMLNODE_TYPE_TAG || c->type == XMLNODE_TYPE_DATA) {
			if (c->type == XMLNODE_TYPE_DATA) {
				pretty = FALSE;
			}
			need_end = TRUE;
		}
	}

	if (need_end) {
		g_string_append_printf(text, ">%s", pretty ? "\n" : "");

		for (c = node->child; c != NULL; c = c->next) {
			if (c->type == XMLNODE_TYPE_TAG) {
				gint esc_len;

				esc = xmlnode_to_str_helper(c, &esc_len, pretty, depth + 1);
				text = g_string_append_len(text, esc, esc_len);
				g_free(esc);
			} else if (c->type == XMLNODE_TYPE_DATA && c->data_size > 0) {
				esc = g_markup_escape_text(c->data, c->data_size);
				text = g_string_append(text, esc);
				g_free(esc);
			}
		}

		if (tab && pretty) {
			text = g_string_append(text, tab);
		}
		if (prefix) {
			g_string_append_printf(text, "</%s:%s>%s", prefix, node_name, formatting ? "\n" : "");
		} else {
			g_string_append_printf(text, "</%s>%s", node_name, formatting ? "\n" : "");
		}
	} else {
		g_string_append_printf(text, "/>%s", formatting ? "\n" : "");
	}

	g_free(node_name);

	g_free(tab);

	if (len) {
		*len = text->len;
	}

	return g_string_free(text, FALSE);
}


/**
 * \brief Convet node to formatted string
 * \param node node
 * \param len pointer to len
 * \return formatted string or NULL on error
 */
gchar *xmlnode_to_formatted_str(xmlnode *node, gint *len)
{
	gchar *xml, *xml_with_declaration;

	g_return_val_if_fail(node != NULL, NULL);

	xml = xmlnode_to_str_helper(node, len, TRUE, 0);
	xml_with_declaration = g_strdup_printf("<?xml version='1.0' encoding='UTF-8' ?>\n\n%s", xml);
	g_free(xml);

	if (len) {
		*len += sizeof("<?xml version='1.0' encoding='UTF-8' ?>\n\n") - 1;
	}

	return xml_with_declaration;
}

gboolean fritzfon_save(router_icl *ri)
{
	xmlnode *node;
	// struct profile *profile = profile_get_active();
	gchar *data;
	gint len;
	SoupBuffer *buffer;

	if (strlen(g_strdup("0")/*g_settings_get_string(fritzfon_settings, "book-owner")*/) > 2) {
		g_warning("Cannot save online address books");
		return FALSE;
	}

	if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	node = phonebook_to_xmlnode();

	data = xmlnode_to_formatted_str(node, &len);
//#define FRITZFON_DEBUG 1
#ifdef FRITZFON_DEBUG
	gchar *file;
	fdebug("len: %d", len);
	file = g_strdup("/tmp/test.xml");
	if (len > 0) {
		file_save(file, data, len);
	}
	g_free(file);
#endif
//	return FALSE;

	buffer = soup_buffer_new(SOUP_MEMORY_TAKE, data, len);

	/* Create POST message */
	gchar *url = g_strdup_printf("http://%s/cgi-bin/firmwarecfg", ri->host/*router_get_host(profile)*/);
	SoupMultipart *multipart = soup_multipart_new(SOUP_FORM_MIME_TYPE_MULTIPART);
	soup_multipart_append_form_string(multipart, "sid", ri->session_id);
	soup_multipart_append_form_string(multipart, "PhonebookId", g_strdup("0")/*g_settings_get_string(fritzfon_settings, "book-owner")*/);
	soup_multipart_append_form_file(multipart, "PhonebookImportFile", "dummy", "text/xml", buffer);
	SoupMessage *msg = soup_form_request_new_from_multipart(url, multipart);

	soup_session_send_message(soup_session, msg);
	soup_buffer_free(buffer);
	g_free(url);

	if (msg->status_code != 200) {
		g_warning("Could not send phonebook");
		g_object_unref(msg);
		return FALSE;
	}
	g_object_unref(msg);

	return TRUE;
}

gboolean fritzfon_remove_contact(router_icl *ri,struct contact *contact)
{
	contacts = (struct contacts*)g_slist_remove((GSList*)contacts, contact);
	return fritzfon_save(ri);
}

/**
 * \brief Put file on FTP
 * \param client ftp client structure
 * \param file file to upload
 * \param path remote path
 * \param data file data
 * \param size file size
 * \return TRUE on success, otherwise FALSE
 */
gboolean ftp_put_file(struct ftp *client, const gchar *file, const gchar *path, gchar *data, gsize size)
{
	gchar *cmd;
	gboolean passive;

#ifdef FTP_DEBUG
	fdebug("ftp_get_file(): TYPE I");
#endif
	ftp_send_command(client, (gchar*)"TYPE I");
#ifdef FTP_DEBUG
	fdebug("ftp_put_file(): code=%d", client->code);
#endif
	if (client->code != 200) {
		return FALSE;
	}

	passive = ftp_passive(client);
#ifdef FTP_DEBUG
	fdebug("ftp_put_file(): passive=%d", passive);
#endif
	if (!passive) {
		return FALSE;
	}

	cmd = g_strconcat("STOR ", path, "/", file, NULL);
#ifdef FTP_DEBUG
	fdebug("ftp_put_file(): %s", cmd);
#endif
	ftp_send_command(client, cmd);
	g_free(cmd);
#ifdef FTP_DEBUG
	fdebug("ftp_put_file(): code=%d", client->code);
#endif
	if (client->code != 150) {
		return FALSE;
	}

	gsize written;
	GError *error = NULL;
#ifdef FTP_DEBUG
	fdebug("ftp_put_file(): write data");
#endif
	g_io_channel_set_buffer_size(client->data, 0);
	gsize chunk = g_io_channel_get_buffer_size(client->data);
	gsize offset = 0;
	gsize write;

	do {
		write = ((size - offset) > chunk) ? chunk : size - offset;
		GIOStatus status = g_io_channel_write_chars(client->data, data + offset, write, &written, &error);
		if (status == G_IO_STATUS_AGAIN) {
			continue;
		}
		if (status != G_IO_STATUS_NORMAL) {
			fdebug("ftp_put_file(): write failed.\n");
			return FALSE;
		}
		g_io_channel_flush(client->data, NULL);
		offset += written;
	} while (offset != size);
#ifdef FTP_DEBUG
	fdebug("ftp_put_file(): done");
#endif
	g_io_channel_shutdown(client->data, TRUE, &error);
	client->data = NULL;

	ftp_read_control_response(client);

	return TRUE;
}
//#define ab
#ifdef ab
void fritzfon_set_image(router_icl *ri,struct contact *contact)
{
	struct fritzfon_priv *priv = g_slice_new0(struct fritzfon_priv);
	//struct profile *profile = profile_get_active();
	//struct ftp *client = ftp_init(router_get_host(profile));
  struct ftp *client = ftp_init(ri->host);
  gchar *volume_path;
	gchar *path;
	gchar *file_name;
	gchar *hash;
	gchar *data;
	gsize size;

	contact->priv = priv;
	//ftp_login(client, router_get_ftp_user(profile), router_get_ftp_password(profile));
  ftp_login(client, ri->ftpusr, ri->ftppwd);

	volume_path = g_settings_get_string(fritzfon_settings, "fax-volume");
	hash = g_strdup_printf("%s%s", volume_path, contact->image_uri);
	file_name = g_strdup_printf("%d.jpg", g_str_hash(hash));
	g_free(hash);
	path = g_strdup_printf("%s/FRITZ/fonpix/", volume_path);
	g_free(volume_path);

	data = file_load(contact->image_uri, &size);
	ftp_put_file(client, file_name, path, data, size);
	ftp_shutdown(client);

	priv->image_url = g_strdup_printf("file:///var/media/ftp/%s%s", path, file_name);
	g_free(path);
	g_free(file_name);
}


gboolean fritzfon_save_contact(router_icl* ri,struct contact *contact)
{
	if (!contact->priv) {
		if (contact->image_uri) {
			fritzfon_set_image(ri,contact);
		}
    contacts = (struct contacts*)g_slist_insert_sorted((GSList*)contacts, contact, contact_name_compare);
	} else {
		if (contact->image_uri) {
			fritzfon_set_image(ri,contact);
		}
	}
	return fritzfon_save(ri);
}

struct fritzfon_book {
  gchar *id;
  gchar *name;
};

static GSList *fritzfon_books = NULL;

struct address_book fritzfon_book = {
	(gchar*)"FritzFon",
	fritzfon_get_active_book_name,
	fritzfon_get_contacts,
	fritzfon_reload_contacts,
	fritzfon_remove_contact,
	fritzfon_save_contact
};

static gint fritzfon_get_books(struct router_icl *ri)
{
  gchar *url;
  SoupMessage *msg;
  gchar *pos = NULL, *data=NULL;
  gint read=0;
  struct fritzfon_book *book = NULL;

  if (!fritzbox_login(ri)/*router_login(profile)*/) {
    return -1;
  }

  url = g_strdup_printf("http://%s/fon_num/fonbook_select.lua", ri->host/*router_get_host(profile)*/);
  msg = soup_form_request_new(SOUP_METHOD_GET, url,
      "sid", ri->session_id,
      NULL);
  g_free(url);

  soup_session_send_message(soup_session, msg);
  if (msg->status_code != 200) {
    g_warning("Could not get fonbook file");
    g_object_unref(msg);
    goto end;
  }

  data = (gchar*)msg->response_body->data;

  read = msg->response_body->length;
  //log_save_data("fritzfon-getbooks.html", data, read);

  g_return_val_if_fail(data != NULL, -2);

  pos = (gchar *)data;
  do {
    pos = strstr(pos, "<label for=\"uiBookid:");
    if (pos) {
      /* Extract ID */
      gchar *end = strstr(pos + 22, "\"");
      g_assert(end != NULL);
      gint len = end - pos - 21;
      gchar *num = (gchar*)g_malloc0(len + 1);
      strncpy(num, pos + 21, len);

      /* Extract Name */
      pos = end;
      end = strstr(pos + 2, "\n");
      g_assert(end != NULL);
      len = end - pos - 1;
      gchar *name = (gchar*)g_malloc0(len);
      strncpy(name, pos + 2, len - 1);
      pos = end;

      book = g_slice_new(struct fritzfon_book);
      book->id = num;
      book->name = name;
      fritzfon_books = g_slist_prepend(fritzfon_books, book);
    } else {
      break;
    }

    pos++;
  } while (pos != NULL);

  g_object_unref(msg);

end:
  if (g_slist_length(fritzfon_books) == 0) {
    book = g_slice_new(struct fritzfon_book);
    book->id = g_strdup("0");
    book->name = g_strdup("Telefonbuch");

    fritzfon_books = g_slist_prepend(fritzfon_books, book);
  }

  //router_logout(profile);

  return 0;
} // static gint fritzfon_get_books(struct router_icl *ri)


static GSList *ab_plugins = NULL;
/**
 * \brief Find address book as requested by profile
 * \param profile profile structure
 * \return address book pointer or NULL on error
 */
struct address_book *address_book_find(/*struct profile *profile*/)
{
//	gchar *name = g_settings_get_string(profile->settings, "address-book");
  gchar *name = g_strdup("FritzFon");
	GSList *list;

	for (list = ab_plugins; list != NULL; list = list->next) {
		struct address_book *ab = list->data;

		if (ab && ab->name && name && !strcmp(ab->name, name)) {
			return ab;
		}
	}

	return ab_plugins ? ab_plugins->data : NULL;
}

/**
 * \brief Get whole contacts within the main internal address book
 * \return contact list
 */
GSList *address_book_get_contacts(void)
{
	GSList *list = NULL;
	struct address_book *ab = address_book_find(/*profile_get_active()*/);

	if (ab) {
		list = ab->get_contacts();
	}

	return list;
}


gboolean fritzfon_reload_contacts(struct router_icl *ri)
{
	return fritzfon_read_book(ri) == 0;
}
#endif


/**
 * \brief Convert incoming fax (ps-format) to tiff (fax-format)
 * \param file_name incoming file name
 * \return tiff file name
 */
gchar *convert_fax_to_tiff(gchar *file_name)
{
	GError *error = NULL;
	gchar *args[12];
	gchar *output;
	gchar *tiff;

	if (strstr(file_name, ".tif")) {
		return file_name;
	}

	tiff = g_strdup_printf("%s.tif", file_name);

	/* convert ps to tiff */
	args[0] = (gchar*)"gs";
	args[1] = (gchar*)"-q";
	args[2] = (gchar*)"-dNOPAUSE";
	args[3] = (gchar*)"-dSAFER";
	args[4] = (gchar*)"-dBATCH";

//	if (g_settings_get_int(profile_get_active()->settings, "fax-controller") < 3) {
  if (1) {
		args[5] = (gchar*)"-sDEVICE=tiffg4";
	} else {
		args[5] = (gchar*)"-sDEVICE=tiffg32d";
	}

	args[6] = (gchar*)"-sPAPERSIZE=a4";
	args[7] = (gchar*)"-dFIXEDMEDIA";
//	if (g_settings_get_int(profile_get_active()->settings, "fax-resolution")) {
  if (1) {
		args[8] = (gchar*)"-r204x196";
	} else {
		args[8] = (gchar*)"-r204x98";
	}
	output = g_strdup_printf("-sOutputFile=%s", tiff);
	args[9] = output;
	args[10] = file_name;
	args[11] = NULL;

	if (!g_spawn_sync(NULL, args, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL, NULL, NULL, &error)) {
		g_warning("Error occurred: %s", error ? error->message : "");
		g_free(tiff);
		return NULL;
	}

	if (!g_file_test(tiff, G_FILE_TEST_EXISTS)) {
		g_free(tiff);
		return NULL;
	}

	return tiff;
}


// hier alles zum Wählen

 static gconstpointer net_event;

struct capi_connection *active_capi_connection = NULL;
static gchar *sff_data = NULL;
static gsize sff_len = 0;
static gsize sff_pos = 0;
#define SFF_CIP 0x11
#include <spandsp.h>
enum fax_phase {
	IDLE = -1,
	CONNECT = 1,
	PHASE_B = 2,
	PHASE_D = 3,
	PHASE_E = 4,
};

struct fax_status {
	gchar tiff_file[256];
	gchar src_no[64];
	gchar trg_no[64];
	gchar ident[64];
	gchar header[64];
	gchar remote_ident[64];

	enum fax_phase phase;
	gint error_code;
	gboolean sending;
	gchar ecm;
	gchar modem;
	gint bitrate;
	gint encoding;
	gint bad_rows;
	gint page_current;
	gint page_total;
	gint bytes_received;
	gint bytes_sent;
	gint bytes_total;
	gboolean manual_hookup;
	gboolean done;
	gboolean progress_status;

	struct capi_connection *connection;

	fax_state_t *fax_state;
};


/* Close recording */
int recording_close(struct recorder *recorder);

static unsigned char *lut_in = NULL;
static unsigned char *lut_out = NULL;
static unsigned char *lut_analyze = NULL;
static short *lut_a2s = NULL;
signed char linear16_2_law[65536];
unsigned short law_2_linear16[256];

/**
 * \brief Return current time in microseconds
 * \return time in microseconds
 */
guint64 microsec_time(void)
{
	struct timeval time_val;

	gettimeofday(&time_val, 0);

	return time_val.tv_sec * ((guint64) 1000000) + time_val.tv_usec;
}


/**
 * \brief Write audio data to record file
 * \param recorder recorder structure
 * \param buf audio buffer
 * \param size size of audio buffer
 * \param channel channel type (local/remote)
 * \return 0 on success, otherwise error
 */
int recording_write(struct recorder *recorder, short *buf, int size, int channel)
{
	gint64 start = recorder->start_time;
	gint64 current, start_pos, position, end_pos;
	int buf_pos, split, delta;
	struct record_channel *buffer;

	if (start == 0) {
		return 0;
	}

	if (size < 1) {
		printf("Warning: Illegal size!\n");
		return -1;
	}

	switch (channel) {
	case RECORDING_LOCAL:
		buffer = &recorder->local;
		break;
	case RECORDING_REMOTE:
		buffer = &recorder->remote;
		break;
	default:
		printf("Recording to unknown channel!\n");
		return -1;
	}

	current = microsec_time() - start;

	end_pos = current * 8000 / 1000000LL;
	start_pos = end_pos - size;
	position = buffer->position;

	if (start_pos >= position - RECORDING_JITTER && start_pos <= position + RECORDING_JITTER) {
		start_pos = position;
		end_pos = position + size;
	}

	if (start_pos < position) {
		delta = (int) position - start_pos;
		start_pos = position;
		buf += delta;
		size -= delta;
		if (size <= 0) {
			return 0;
		}
	}

	buf_pos = start_pos % RECORDING_BUFSIZE;

	if (buf_pos + size <= RECORDING_BUFSIZE) {
		memcpy(buffer->buffer + buf_pos, buf, size * sizeof(short));
	} else {
		split = RECORDING_BUFSIZE - buf_pos;
		memcpy(buffer->buffer + buf_pos, buf, split * sizeof(short));
		buf += split;
		size -= split;
		memcpy(buffer->buffer, buf, size * sizeof(short));
	}

	buffer->position = end_pos;

	return 0;
}

/**
 * \brief Convert audio format to isdn format
 * \param connection active capi connection
 * \param in_buf input buffer
 * \param in_buf_len length of input buffer
 * \param out_buffer output buffer
 * \param out_buf_len pointer to output buffer len
 */
void convert_audio_to_isdn(struct capi_connection *connection, unsigned char *in_buf, unsigned int in_buf_len, unsigned char *out_buf, unsigned int *out_buf_len, short *rec_buf)
{
	unsigned int index;
	unsigned int to_process;
	unsigned int out_ptr = 0;
	unsigned int j;
	unsigned char sample;
	double ratio_out = 1.0f;
	double ll_ratio;
	int max = 0;
	unsigned char sample_u8;

	out_ptr = 0;

	for (index = 0; index < in_buf_len; index += 2) {
		to_process = (int) floor((double)(out_ptr + 1) * ratio_out) - (int) floor((double) out_ptr * ratio_out);

		for (j = 0; j < to_process; j++) {
			int tmp = (int)(in_buf[index]) | ((int)(in_buf[index + 1]) << 8);
			sample = lut_out[tmp];

			if (connection != NULL && connection->mute != 0) {
				sample = lut_out[0];
			}

			sample_u8 = lut_analyze[sample];
			if (abs((int) sample_u8 - 128) > max) {
				max = abs((int) sample_u8 - 128);
			}

			if (connection != NULL) {
				rec_buf[out_ptr] = connection->recorder.file ? lut_a2s[sample] : 0;
			} else {
				rec_buf[out_ptr] = 0;
			}

			out_buf[out_ptr] = sample;
			out_ptr++;
		}
	}

	/* Record data */
	if (connection != NULL && connection->recorder.file != NULL && rec_buf != NULL) {
		recording_write(&connection->recorder, rec_buf, out_ptr, RECORDING_LOCAL);
	}

	ll_ratio = out_ptr / 400.0f;
	if (ll_ratio > 1.0) {
		ll_ratio = 1.0;
	}

	connection->line_level_out_state = connection->line_level_out_state * (1.0 - ll_ratio) + ((double) max / 128) * ll_ratio;

	*out_buf_len = out_ptr;
}



/**
 * \brief Flush recording buffer
 * \param recorder recording structure
 * \param last last call flag
 * \return 0 on success, otherwise error
 */
int recording_flush(struct recorder *recorder, guint last)
{
	gint64 max_position = recorder->local.position;
	gint64 tmp = recorder->remote.position;
	gint64 start_position = recorder->last_write;
	short rec_buf[RECORDING_BUFSIZE * 2];
	gint64 src_ptr, dst_ptr, size;

	if (recorder->start_time == 0) {
		return 0;
	}

	if (tmp > max_position) {
		max_position = tmp;
	}

	if (start_position + (RECORDING_BUFSIZE * 7 / 8) < max_position) {
		start_position = max_position - (RECORDING_BUFSIZE * 7 / 8);
	}

	if (!last) {
		max_position -= RECORDING_BUFSIZE / 8;
	}

	size = (gint64)(max_position - start_position);
	if (max_position == 0 || start_position >= max_position || (!last && size < RECORDING_BUFSIZE / 8)) {
		return 0;
	}

	dst_ptr = 0;
	src_ptr = start_position % RECORDING_BUFSIZE;

	while (--size) {
		rec_buf[dst_ptr++] = recorder->local.buffer[src_ptr];
		recorder->local.buffer[src_ptr] = 0;
		rec_buf[dst_ptr++] = recorder->remote.buffer[src_ptr];
		recorder->remote.buffer[src_ptr] = 0;

		if (++src_ptr >= RECORDING_BUFSIZE) {
			src_ptr = 0;
		}
	}

	sf_writef_short(recorder->file, rec_buf, dst_ptr / 2);

	recorder->last_write = max_position;

	return 0;
}

/**
 * \brief Close recording structure
 * \param recorder recorder structure
 * \return 0 on success, otherwise error
 */
int recording_close(struct recorder *recorder)
{
	int result = 0;

	if (recorder->start_time) {
		if (recording_flush(recorder, 1) < 0) {
			result = -1;
		}
		recorder->start_time = 0;

		if (recorder->file_name) {
			free(recorder->file_name);
			recorder->file_name = NULL;
		}

		if (sf_close(recorder->file) != 0) {
			printf("Error closing record file!\n");
			result = -1;
		}
	}

	return result;
}

/**
 * \brief Input audio handler
 * \param data capi connection pointer
 * \return NULL
 */
gpointer phone_input_thread(gpointer data)
{
	struct session *session = faxophone_get_session();
	struct capi_connection *connection = (capi_connection*)data;
	guchar audio_buffer_rx[CAPI_PACKETS];
	guchar audio_buffer[CAPI_PACKETS * 2];
	guint audio_buf_len;
	short rec_buffer[CAPI_PACKETS];
	_cmsg cmsg;

	while (session->input_thread_state == 1) {
		int len;

		len = session->handlers->audio_input(connection->audio, (guchar *) audio_buffer_rx, sizeof(audio_buffer_rx));

		/* Check if we have some audio data to process */
		if (len > 0) {
			/* convert audio data to isdn format */
			convert_audio_to_isdn(connection, (guchar *) audio_buffer_rx, len, audio_buffer, &audio_buf_len, rec_buffer);

			isdn_lock();
			DATA_B3_REQ(&cmsg, session->appl_id, 0, connection->ncci, audio_buffer, audio_buf_len, session->message_number++, 0);
			isdn_unlock();
		}
	}

	session->input_thread_state = 0;

	if (connection->recording == 1) {
		recording_close(&connection->recorder);
	}

	return NULL;
}


void phone_init_data(struct capi_connection *connection)
{
	struct session *session = faxophone_get_session();

	fdebug("phone_init_data()");
	if (session->input_thread_state == 0) {
		session->input_thread_state = 1;

		CREATE_THREAD("phone-input", phone_input_thread, connection);
	}
}

/**
 * \brief Convert isdn format to audio format
 * \param in_buf input buffer
 * \param in_buf_len length of input buffer
 * \param out_buffer output buffer
 * \param out_buf_len pointer to output buffer len
 */
void convert_isdn_to_audio(struct capi_connection *connection, unsigned char *in_buf, unsigned int in_buf_len, unsigned char *out_buf, unsigned int *out_buf_len, short *rec_buf)
{
	struct recorder *recorder = &connection->recorder;
	unsigned int index;
	unsigned int to_process;
	unsigned int out_ptr = 0;
	unsigned int j;
	unsigned char in_byte;
	int sample;
	double ratio_in = 1.0f;
	double ll_ratio;
	int max = 0;

	out_ptr = 0;

	for (index = 0; index < in_buf_len; index++) {
		in_byte = in_buf[index];

		if (recorder != NULL && rec_buf != NULL) {
			rec_buf[index] = recorder->file ? lut_a2s[in_byte] : 0;
		}

		sample = lut_analyze[in_byte];
		if (abs((int) sample - 128) > max) {
			max = abs((int) sample - 128);
		}

		to_process = (int) floor((double)(index + 1) * ratio_in) - (int) floor((double) index * ratio_in);

		for (j = 0; j < to_process; j++) {
			out_buf[out_ptr++] = lut_in[(int) in_byte * 2];
			out_buf[out_ptr++] = lut_in[(int) in_byte * 2 + 1];
		}
	}

	/* Record data */
	if (recorder != NULL && rec_buf != NULL) {
		recording_write(recorder, rec_buf, in_buf_len, RECORDING_REMOTE);
	}

	ll_ratio = in_buf_len / 400.0f;
	if (ll_ratio > 1.0) {
		ll_ratio = 1.0;
	}

	if (connection) {
		connection->line_level_in_state = connection->line_level_in_state * (1.0 - ll_ratio) + ((double) max / 128) * ll_ratio;
	}

	*out_buf_len = out_ptr;
}
/**
 * \brief Phone transfer routine which accepts incoming data, converts and outputs the audio
 * \param connection active capi connection
 * \param sCapiMessage current capi message
 */
void phone_transfer(struct capi_connection *connection, _cmsg capi_message)
{
	struct session *session = faxophone_get_session();
	_cmsg cmsg;
	guchar audio_buffer[CAPI_PACKETS * 2];
	guint len = DATA_B3_IND_DATALENGTH(&capi_message);
	guint audio_buf_len;
	short rec_buffer[8192];

	/* convert isdn to audio format */
	convert_isdn_to_audio(connection, DATA_B3_IND_DATA(&capi_message), len, audio_buffer, &audio_buf_len, rec_buffer);
	/* Send capi response */
	isdn_lock();
	DATA_B3_RESP(&cmsg, session->appl_id, session->message_number++, connection->ncci, DATA_B3_IND_DATAHANDLE(&capi_message));
	isdn_unlock();

	/* Send data to soundcard */
	session->handlers->audio_output(connection->audio, audio_buffer, audio_buf_len);
}

static uint16_t *_law_2_linear16 = &law_2_linear16[0];

/**
 * \brief Process rx data through spandsp
 * \param fax_state fax state information
 * \param buf receive buffer
 * \param len length of buffer
 * \return error code
 */
gint spandsp_rx(fax_state_t *fax_state, uint8_t *buf, size_t len)
{
	int16_t buf_in[CAPI_PACKETS];
	int16_t *wave;
	gint err, i;

	wave = buf_in;

	for (i = 0; i != len; ++i, ++wave) {
		*wave = _law_2_linear16[(uint8_t) buf[i]];
	}

	err = fax_rx(fax_state, buf_in, CAPI_PACKETS);

	return err;
}

static int8_t *_linear16_2_law = (int8_t *) &linear16_2_law[32768];
/**
 * \brief TX direction
 * \param fax_state fax state
 * \param buf transfer buffer
 * \param len length of buffer
 * \return error code
 */
gint spandsp_tx(fax_state_t *fax_state, uint8_t *buf, size_t len)
{
	int16_t buf_in[CAPI_PACKETS];
	uint8_t *alaw;
	gint err, i;

	err = fax_tx(fax_state, buf_in, CAPI_PACKETS);
	alaw = buf;

	for (i = 0; i != len; ++i, ++alaw) {
		*alaw = _linear16_2_law[(int16_t) buf_in[i]];
	}

	return err;
}


/**
 * \brief Receive/Transmit fax state
 * \param connection capi connection pointer
 * \param capi_message current capi message
 */
void fax_transfer(struct capi_connection *connection, _cmsg capi_message)
{
	struct fax_status *status = (fax_status*)connection->priv;
	struct session *session = faxophone_get_session();
	_cmsg cmsg;
	guint8 alaw_buffer_tx[CAPI_PACKETS];
	gint32 len = DATA_B3_IND_DATALENGTH(&capi_message);

	/* RX/TX spandsp */
	spandsp_rx(status->fax_state, DATA_B3_IND_DATA(&capi_message), len);
	//isdn_lock();
	DATA_B3_RESP(&cmsg, session->appl_id, session->message_number++, connection->ncci, DATA_B3_IND_DATAHANDLE(&capi_message));
	//isdn_unlock();


	/* Send data to remote */
	len = CAPI_PACKETS;
	spandsp_tx(status->fax_state, alaw_buffer_tx, len);
	//isdn_lock();
	DATA_B3_REQ(&cmsg, session->appl_id, 0, connection->ncci, (void *) alaw_buffer_tx, len, session->message_number++, 0);
	//isdn_unlock();
}

/**
 * \brief Close spandsp
 * \param fax_state fax state
 * \return error code
 */
gint spandsp_close(fax_state_t *fax_state)
{
	struct fax_status *status = NULL;
	struct session *session = faxophone_get_session();
	gint i;

	fdebug("Close");
	if (fax_state != NULL) {
		fax_release(fax_state);
	} else {
		for (i = 0; i < CAPI_CONNECTIONS; i++) {
			status = (fax_status*)session->connection[i].priv;

			if (status != NULL) {
				fax_release(status->fax_state);
			}
		}
	}

	return 0;
}


/**
 * \brief Cleanup private fax structure from capi connection
 * \param connection capi connection
 */
void fax_clean(struct capi_connection *connection)
{
	struct fax_status *status = (fax_status*)connection->priv;

	spandsp_close(status->fax_state);

	free(status);
	connection->priv = NULL;
}


/**
 * \brief Receive/Transmit fax state
 * \param connection capi connection pointer
 * \param capi_message current capi message
 */
static inline void sff_transfer(struct capi_connection *connection, _cmsg capi_message)
{
	struct session *session = faxophone_get_session();
	struct fax_status *status = (fax_status*)connection->priv;
	_cmsg cmsg;
	gint transfer = CAPI_PACKETS;

	fdebug("processing fax");

	if (sff_len - sff_pos < transfer) {
		transfer = sff_len - sff_pos;
	}

	isdn_lock();
	DATA_B3_REQ(&cmsg, session->appl_id, 0, connection->ncci, sff_data + sff_pos, transfer, session->message_number++, 0);
	isdn_unlock();

	sff_pos += transfer;

	status->bytes_total = sff_len;
	status->bytes_sent = sff_pos;

	status->progress_status = 1;
	if (session->handlers && session->handlers->status) {
		session->handlers->status(connection, 1);
	}

	if (sff_pos == sff_len) {
		fdebug("EOF");
	} else {
		fdebug("Pos: %" G_GSIZE_FORMAT "/%" G_GSIZE_FORMAT " (%" G_GSIZE_FORMAT "%%)", sff_pos, sff_len, sff_pos * 100 / sff_len);
	}
}


gpointer sff_transfer_thread(gpointer data)
{
	struct capi_connection *connection = (capi_connection*)data;
	_cmsg cmsg;

	while (connection->state == STATE_CONNECTED && sff_pos < sff_len) {
		if (connection->use_buffers && connection->buffers < CAPI_BUFFERCNT) {
			fdebug("Buffers: %d", connection->buffers);
			sff_transfer(connection, cmsg);
			connection->buffers++;
		}

		g_usleep(50);
	}

	capi_hangup(connection);

	while (connection->state == STATE_CONNECTED && connection->buffers) {
		g_usleep(50);
	}


	return NULL;
}


void sff_init_data(struct capi_connection *connection)
{
	g_thread_new("sff transfer", sff_transfer_thread, connection);
}

/**
 * \brief Cleanup private fax structure from capi connection
 * \param connection capi connection
 */
void sff_clean(struct capi_connection *connection)
{
	connection->priv = NULL;
}


static int capi_set_free(struct capi_connection *connection);
static int capi_connection_set_type(struct capi_connection *connection, int type);
static void capi_error(long error);
struct capi_connection *capi_call(
	unsigned controller,
	const char *src_no,
	const char *trg_no,
	unsigned call_anonymous,
	unsigned type,
	unsigned cip,
	_cword b1_protocol,
	_cword b2_protocol,
	_cword b3_protocol,
	_cstruct b1_configuration,
	_cstruct b2_configuration,
	_cstruct b3_configuration);


/**
 * \brief Send Fax
 * \param sff_file The sff file to send
 * \param modem 0-3 (2400-14400)
 * \param ecm Error correction mode (on/off)
 * \param controller The controller for sending the fax
 * \param src_no MSN
 * \param trg_no Target fax number
 * \param ident Fax ident
 * \param header Fax header line
 * \param call_anonymous Send fax anonymous
 * \return error code
 */
struct capi_connection *sff_send(gchar *sff_file, gint modem, gint ecm, gint controller, const gchar *src_no, const gchar *trg_no, const gchar *ident, const gchar *header, gint call_anonymous)
{
	struct capi_connection *connection;
	_cstruct b1;
	_cstruct b2;
	_cstruct b3;
	int i = 0, j;

	fdebug(" ** SFF **");
	fdebug("sff: %s, modem: %d, ecm: %s, controller: %d, src: %s, trg: %s, ident: %s, header: %s, anonymous: %d)", sff_file, modem, ecm ? "on" : "off", controller, src_no, trg_no, (ident != NULL ? ident : "(null)"), (header != NULL ? header : "(null)"), call_anonymous);

	b1 = (_cstruct)g_malloc0(2 + 2 + 2 + 2);
	b2 = NULL;
	b3 = (_cstruct)g_malloc0(1 + 2 + 2 + 1 + strlen(ident) + 1 + strlen(header));

	/* Length */
	b3[i++] = 1 + 2 + 2 + 1 + strlen(ident) + 1 + strlen(header);
	/* Resolution: Standard = 0x00, High = 0x01 */
	b3[i++] = 0;
	b3[i++] = 0;
	/* Format: SFF */
	b3[i++] = 0;
	b3[i++] = 0;

	/* Station ID */
	b3[i++] = strlen(ident);
	for (j = 0; j < strlen(ident); j++) {
		b3[i++] = ident[j];
	}

	/* Header */
	b3[i++] = strlen(header);
	for (j = 0; j < strlen(header); j++) {
		b3[i++] = header[j];
	}

	/* Open SFF file */
	sff_data = file_load(sff_file, &sff_len);
	sff_pos = 0;

	connection = capi_call(controller, src_no, trg_no, (guint) call_anonymous, SESSION_SFF, SFF_CIP, 4, 4, 4, b1, b2, b3);
	if (connection) {
    fdebug("Verbindung aufgebaut\n");
		struct fax_status *status = NULL;

		connection->buffers = 0;
		connection->use_buffers = TRUE;

		status = (fax_status*)malloc(sizeof(struct fax_status));
		memset(status, 0, sizeof(struct fax_status));

		connection->priv = status;
  } else {
    fdebug("Verbindung misslungen\n");
	}

	return connection;
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

/**
 * \brief Phase B handler
 * \param state t30 state pointer
 * \param user_data pointer to connection
 * \param result result
 * \return error code
 */
static gint phase_handler_b(t30_state_t *state, void *user_data, gint result)
{
	struct capi_connection *connection = (capi_connection*)user_data;
	struct fax_status *status = (fax_status*)connection->priv;
	struct session *session = faxophone_get_session();
	t30_stats_t stats;
	t30_state_t *t30;
	const gchar *ident;

	t30_get_transfer_statistics(state, &stats);
	t30 = fax_get_t30_state(status->fax_state);

	fdebug("Phase B handler (0x%X) %s", result, t30_frametype(result));
	fdebug(" - bit rate %d", stats.bit_rate);
	fdebug(" - ecm %s", (stats.error_correcting_mode) ? "on" : "off");

	if (status->sending) {
		ident = t30_get_rx_ident(t30);
	} else {
		ident = t30_get_tx_ident(t30);
	}
	snprintf(status->remote_ident, sizeof(status->remote_ident), "%s", ident ? ident : "");
	fdebug("Remote side: '%s'", status->remote_ident);
	if (t30_get_rx_sender_ident(t30)) {
		fdebug("Remote side sender: '%s'", t30_get_rx_sender_ident(t30));
	}
	if (t30_get_rx_country(t30)) {
		fdebug("Remote side country: '%s'", t30_get_rx_country(t30));
	}
	if (t30_get_rx_vendor(t30)) {
		fdebug("Remote side vendor: '%s'", t30_get_rx_vendor(t30));
	}
	if (t30_get_rx_model(t30)) {
		fdebug("Remote side model: '%s'", t30_get_rx_model(t30));
	}

	status->phase = PHASE_B;
	status->bytes_sent = 0;
	status->bytes_total = 0;
	status->bytes_received = 0;
	status->ecm = stats.error_correcting_mode;
	status->bad_rows = stats.bad_rows;
	status->encoding = stats.encoding;
	status->bitrate = stats.bit_rate;
	//status->page_total = stats.pages_in_file;
	status->progress_status = 0;

	status->page_current = status->sending ? stats.pages_tx + 1 : stats.pages_rx + 1;

	session->handlers->status(connection, 0);

	return 0;
}

/**
 * \brief Phase D handler
 * \param state t30 state pointer
 * \param user_data pointer to connection
 * \param result result
 * \return error code
 */
static gint phase_handler_d(t30_state_t *state, void *user_data, gint result)
{
	struct capi_connection *connection = (capi_connection*)user_data;
	struct fax_status *status = (fax_status*)connection->priv;
	struct session *session = faxophone_get_session();
	t30_stats_t stats;

	t30_get_transfer_statistics(state, &stats);

	fdebug("Phase D handler (0x%X) %s", result, t30_frametype(result));
	fdebug(" - pages transferred %d", status->sending ? stats.pages_tx : stats.pages_rx);
	/*fdebug(" - image size %d x %d", stats.width, stats.length);
	fdebug(" - bad rows %d", stats.bad_rows);
	fdebug(" - longest bad row run %d", stats.longest_bad_row_run);
	fdebug(" - image size %d", stats.image_size);*/

	status->phase = PHASE_D;
	/*status->ecm = stats.error_correcting_mode;
	status->bad_rows = stats.bad_rows;
	status->encoding = stats.encoding;
	status->bitrate = stats.bit_rate;*/

	if (status->sending) {
		status->page_current = (stats.pages_in_file >= stats.pages_tx + 1 ? stats.pages_tx + 1 : stats.pages_tx);
	} else {
		status->page_current = stats.pages_rx;
	}

	//status->page_total = stats.pages_in_file;
	status->bytes_received = 0;
	status->bytes_sent = 0;
	status->progress_status = 0;

	session->handlers->status(connection, 0);

	return 0;
}

/**
 * \brief Phase E handler
 * \param state T30 state
 * \param user_data pointer to current capi connection
 * \param result result code
 */
static void phase_handler_e(t30_state_t *state, void *user_data, gint result)
{
	struct capi_connection *connection = (capi_connection*)user_data;
	struct fax_status *status = (fax_status*)connection->priv;
	struct session *session = faxophone_get_session();
	gint transferred = 0;
	t30_stats_t stats;
	t30_state_t *t30;
	const gchar *ident;

	t30_get_transfer_statistics(state, &stats);

	fdebug("Phase E handler (0x%X) %s", result, t30_completion_code_to_str(result));

	transferred = status->sending ? stats.pages_tx : stats.pages_rx;
	fdebug(" - pages transferred %d", transferred);
	/*fdebug(" - image resolution %d x %d", stats.x_resolution, stats.y_resolution);
	fdebug(" - compression type %d", stats.encoding);
	fdebug(" - coding method %s", t4_encoding_to_str(stats.encoding));*/

	status->phase = PHASE_E;
	/*status->ecm = stats.error_correcting_mode;
	status->bad_rows = stats.bad_rows;
	status->encoding = stats.encoding;
	status->bitrate = stats.bit_rate;*/

	status->page_current = (status->sending ? stats.pages_tx : stats.pages_rx);
	//status->page_total = stats.pages_in_file;
	status->error_code = result;

	t30 = fax_get_t30_state(status->fax_state);
	if (status->sending) {
		ident = t30_get_rx_ident(t30);
	} else {
		ident = t30_get_tx_ident(t30);
	}
	status->progress_status = 0;

	snprintf(status->remote_ident, sizeof(status->remote_ident), "%s", ident ? ident : "");
	fdebug("Remote station id: %s", status->remote_ident);

	session->handlers->status(connection, 0);
}

/**
 * \brief Realtime frame handler which keeps tracks of data transfer
 * \param state t30 state pointer
 * \param user_data pointer to connection index
 * \param direction transmission direction
 * \param msg spandsp message
 * \param len len of frame
 */
static void real_time_frame_handler(t30_state_t *state, void *user_data, gint direction, const uint8_t *msg, gint len)
{
	struct capi_connection *connection = (capi_connection*)user_data;
	struct fax_status *status = (fax_status*)connection->priv;
	struct session *session = faxophone_get_session();
	t30_stats_t stats;

	//fdebug("real_time_frame_handler() called (%d/%d/%d)", direction, len, msg[2]);
	if (msg[2] == 6) {
		t30_get_transfer_statistics(state, &stats);

		if (status->sending) {
			status->bytes_total = stats.image_size;
			status->bytes_sent += len;
		} else {
			status->bytes_received += len;
			status->bytes_total += len;
		}

		status->progress_status = 1;
		session->handlers->status(connection, 1);
	}
}



/**
 * \brief Initialize spandsp
 * \param tiff_file tiff file
 * \param sending sending flag
 * \param modem supported modem
 * \param ecm error correction mode flag
 * \param lsi lsi
 * \param local_header_info local header
 * \param connection capi connection poiner
 * \return error code
 */
gint spandsp_init(const gchar *tiff_file, gboolean sending, gchar modem, gchar ecm, const gchar *lsi, const gchar *local_header_info, struct capi_connection *connection)
{
	t30_state_t *t30;
	logging_state_t *log_state;
	gint supported_resolutions = 0;
	gint supported_image_sizes = 0;
	gint supported_modems = 0;
	struct fax_status *status = (fax_status*)connection->priv;

	status->fax_state = fax_init(NULL, sending);
	fdebug("status->fax_state: %p", status->fax_state);

	fax_set_transmit_on_idle(status->fax_state, TRUE);
	fax_set_tep_mode(status->fax_state, FALSE);

	t30 = fax_get_t30_state(status->fax_state);

	/* Supported resolutions */
	supported_resolutions = 0;
	supported_resolutions |= T30_SUPPORT_STANDARD_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_FINE_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_SUPERFINE_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_R8_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_R16_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_300_300_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_400_400_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_600_600_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_1200_1200_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_300_600_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_400_800_RESOLUTION;
	supported_resolutions |= T30_SUPPORT_600_1200_RESOLUTION;

	/* Supported image sizes */
	supported_image_sizes = 0;
	supported_image_sizes |= T30_SUPPORT_215MM_WIDTH;
	supported_image_sizes |= T30_SUPPORT_255MM_WIDTH;
	supported_image_sizes |= T30_SUPPORT_303MM_WIDTH;
	supported_image_sizes |= T30_SUPPORT_UNLIMITED_LENGTH;
	supported_image_sizes |= T30_SUPPORT_A4_LENGTH;
	supported_image_sizes |= T30_SUPPORT_US_LETTER_LENGTH;
	supported_image_sizes |= T30_SUPPORT_US_LEGAL_LENGTH;

	/* Supported modems */
	supported_modems = 0;
	if (modem > 0) {
		supported_modems |= T30_SUPPORT_V27TER;
		if (modem > 1) {
			supported_modems |= T30_SUPPORT_V29;
		}
		if (modem > 2) {
			supported_modems |= T30_SUPPORT_V17;
		}
#if defined(T30_SUPPORT_V34)
		if (modem > 3) {
			supported_modems |= T30_SUPPORT_V34;
		}
#endif
	}

	t30_set_supported_modems(t30, supported_modems);

	/* Error correction */
	if (ecm) {
		/* Supported compressions */
#if defined(SPANDSP_SUPPORT_T85)
		t30_set_supported_compressions(t30, T30_SUPPORT_T4_1D_COMPRESSION | T30_SUPPORT_T4_2D_COMPRESSION | T30_SUPPORT_T6_COMPRESSION | T30_SUPPORT_T85_C
#else
		t30_set_supported_compressions(t30, T30_SUPPORT_T4_1D_COMPRESSION | T30_SUPPORT_T4_2D_COMPRESSION | T30_SUPPORT_T6_COMPRESSION);
#endif

		t30_set_ecm_capability(t30, ecm);
	}

	t30_set_supported_t30_features(t30, T30_SUPPORT_IDENTIFICATION | T30_SUPPORT_SELECTIVE_POLLING | T30_SUPPORT_SUB_ADDRESSING);
	t30_set_supported_resolutions(t30, supported_resolutions);
	t30_set_supported_image_sizes(t30, supported_image_sizes);

	/* spandsp loglevel */
  /*
	if (log_level >= 1) {
		log_state = t30_get_logging_state(t30);
		span_log_set_level(log_state, 0xFFFFFF);

		if (!logging) {
			logging = spandsp_msg_log;
		}

		span_log_set_message_handler(log_state, logging);
	}
  */

	if (lsi) {
		t30_set_tx_ident(t30, lsi);
	}
	if (local_header_info) {
		t30_set_tx_page_header_info(t30, local_header_info);
	}

	if (sending == TRUE) {
		t30_set_tx_file(t30, tiff_file, -1, -1);
		status->page_total = get_tiff_total_pages(tiff_file);
	} else {
		t30_set_rx_file(t30, tiff_file, -1);
	}

	t30_set_phase_b_handler(t30, phase_handler_b, (void *) connection);
	t30_set_phase_d_handler(t30, phase_handler_d, (void *) connection);
	t30_set_phase_e_handler(t30, phase_handler_e, (void *) connection);

	t30_set_real_time_frame_handler(t30, real_time_frame_handler, (void *) connection);

	return 0;
}


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
struct capi_connection *fax_send(gchar *tiff_file, gint modem, gint ecm, gint controller, gint cip, const gchar *src_no, const gchar *trg_no, const gchar *lsi, const gchar *local_header_info, gint call_anonymous)
{
	struct fax_status *status;
	struct capi_connection *connection;

	fdebug("tiff: %s, modem: %d, ecm: %s, controller: %d, src: %s, trg: %s, ident: %s, header: %s, anonymous: %d)", tiff_file, modem, ecm ? "on" : "off", controller, src_no, trg_no, (lsi != NULL ? lsi : "(null)"), (local_header_info != NULL ? local_header_info : "(null)"), call_anonymous);

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


#define SPEECH_CIP			0x04
#define FAX_CIP				0x11

/**
 * \brief Dial number via fax
 * \param tiff tiff file name
 * \param trg_no target number
 * \param suppress suppress number flag
 * \return capi connection pointer
 */
struct capi_connection *fax_dial(router_icl *ri,gchar *tiff, const gchar *trg_no, gboolean suppress)
{
//	struct profile *profile = profile_get_active();
	gint modem = 2;//g_settings_get_int(profile->settings, "fax-bitrate");
	gboolean ecm = 1;//g_settings_get_boolean(profile->settings, "fax-ecm");
	gint controller = 5;//g_settings_get_int(profile->settings, "fax-controller") + 1;
	gint cip = 0;//g_settings_get_int(profile->settings, "fax-cip");
	const gchar *src_no = g_strdup("616381");//g_settings_get_string(profile->settings, "fax-number");
	const gchar *header = g_strdup("DiabDachau");//g_settings_get_string(profile->settings, "fax-header");
	const gchar *ident = g_strdup("+49");//g_settings_get_string(profile->settings, "fax-ident");
	struct capi_connection *connection = NULL;
	gchar *target;

	if (EMPTY_STRING(src_no)) {
		emit_message(0, (gchar*)"Source MSN not set, cannot dial");
		return NULL;
	}

	target = call_canonize_number(ri,trg_no);

	if (cip == 1) {
		cip = FAX_CIP;
		fdebug("Using 'ISDN Fax' id");
	} else {
		cip = SPEECH_CIP;
		fdebug("Using 'Analog Fax' id");
	}

	if (111389944/*g_settings_get_boolean(profile->settings, "fax-sff")*/) {
		connection = sff_send(tiff, modem, ecm, controller, src_no, target, ident, header, suppress);
	} else {
		connection = fax_send(tiff, modem, ecm, controller, cip, src_no, target, ident, header, suppress);
	}
	g_free(target);

	return connection;
}

#define PHONE_CIP 0x04

/**
 * \brief Dial a given number and set connection type to SESSION_PHONE
 * \param nController capi controller
 * \param source source number (own MSN)
 * \param target remote number (we want to dial)
 * \param anonymous anonymous flag (suppress number)
 * \return seee capiCall
 */
struct capi_connection *phone_call(guchar controller, const char *source, const char *target, gboolean anonymous)
{
	return capi_call(controller, source, target, anonymous, SESSION_PHONE, PHONE_CIP, 1, 1, 0, NULL, NULL, NULL);
}


/**
 * \brief Dial number via phone
 * \param trg_no target number
 * \param suppress suppress number flag
 * \return capi connection pointer
 */
struct capi_connection *phone_dial(router_icl *ri,const gchar *trg_no, gboolean suppress)
{
	//struct profile *profile = profile_get_active();
	gint controller = 5;//g_settings_get_int(profile->settings, "phone-controller") + 1;
	const gchar *src_no = "616381";//g_settings_get_string(profile->settings, "phone-number");
	struct capi_connection *connection = NULL;
	gchar *target;

	if (EMPTY_STRING(src_no)) {
		emit_message(0, (gchar*)"Source MSN not set, cannot dial");
		return NULL;
	}

	target = call_canonize_number(ri,trg_no);

	connection = phone_call(controller, src_no, target, suppress);

	g_free(target);

	return connection;
}

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

	fdebug("connection_ring() src %s trg %s", capi_connection->source, capi_connection->target);
	connection = connection_find_by_number(capi_connection->source);
#if ACCEPT_INTERN
	if (!connection && !strncmp(capi_connection->source, "**", 2)) {
		connection = connection_add_call(981, CONNECTION_TYPE_INCOMING, capi_connection->source, capi_connection->target);
	}
#endif

	fdebug("connection_ring() connection %p", connection);
	if (connection) {
		fdebug("connection_ring() set capi_connection %p", capi_connection);
		connection->priv = capi_connection;

    printf("Verbindungs-Notifikation\n");
//		emit_connection_notify(connection);
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
	fdebug("connection_code(): code 0x%x", code);
}

/**
 * \brief Connection status handlers - emits connection-status signal
 * \param connection capi connection structure
 * \param status status code
 */
void connection_status(struct capi_connection *connection, gint status)
{
  printf("Verbindungsstatus: %d\n",status);
	//emit_connection_status(status, connection);
}

gboolean connection_established_idle(gpointer data)
{
	struct capi_connection *connection = (capi_connection*)data;

  printf("Verbindung hergestellt\n");
	//emit_connection_established(connection);

	return G_SOURCE_REMOVE;
}

void connection_established(struct capi_connection *connection)
{
	g_idle_add(connection_established_idle, connection);
}


/** Audio device structure */
struct audio {
	/* Name of plugin */
	const gchar *name;
	/* Initialize function */
	gboolean (*init)(guchar channels, gushort rate, guchar bits);
	/* Open device for playback */
	gpointer (*open)(void);
	/* Write data to audio device */
	gsize (*write)(gpointer priv, guchar *buffer, gsize len);
	/* Read data of audio device */
	gsize (*read)(gpointer priv, guchar *buffer, gsize max_len);
	/* Close audio device */
	gboolean (*close)(gpointer priv);
	/* Shutdown audio device */
	gboolean (*deinit)(void);
	/* Get possible audio input/output devices */
	GSList *(*get_devices)(void);
};

gboolean connection_terminated_idle(gpointer data)
{
	struct capi_connection *connection = (capi_connection*)data;

  printf("Verbindung beendet\n");
	//emit_connection_terminated(connection);

	return G_SOURCE_REMOVE;
}

void connection_terminated(struct capi_connection *connection)
{
	g_idle_add(connection_terminated_idle, connection);
}

/** global pointer to current used audio plugin */
static struct audio *internal_audio = NULL;

static GSList *audio_list = NULL;

/**
 * \brief Open current audio plugin
 * \return private audio data pointer or NULL on error
 */
gpointer audio_open(void)
{
	if (!internal_audio) {
		return NULL;
	}

	return internal_audio->open();
}

/**
 * \brief Read of audio plugin
 * \param audio_priv private audio data (see audio_open)
 * \param data data pointer
 * \param size number of bytes to read
 * \return number of bytes read or -1 on error
 */
gsize audio_read(gpointer audio_priv, guchar *data, gsize size)
{
	if (!internal_audio) {
		return -1;
	}

	return internal_audio->read(audio_priv, data, size);
}


/**
 * \brief Write data to audio plugin
 * \param audio_priv private audio data (see audio_open)
 * \param data data to write to audio device
 * \param size number of bytes to write
 * \return number of bytes written or -1 on error
 */
gsize audio_write(gpointer audio_priv, guchar *data, gsize size)
{
	if (!internal_audio) {
		return -1;
	}

	return internal_audio->write(audio_priv, data, size);
}


/**
 * \brief Close current audio device
 * \param audio_priv private audio data (see audio_open)
 * \return TRUE on success, otherwise FALSE
 */
gboolean audio_close(gpointer audio_priv)
{
	if (!internal_audio) {
		return FALSE;
	}

	return internal_audio->close(audio_priv);
}


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


/**
 * \brief Depending on type get dialport
 * \param type phone type
 * \return dialport
 */
gint fritzbox_get_dialport(gint type)
{
	gint index;

	for (index = 0; index < PORT_MAX; index++) {
		if (fritzbox_phone_ports[index].type == type) {
			return fritzbox_phone_ports[index].number;
		}
	}

	return -1;
}

static gint fritzbox_get_dial_port(router_icl *ri)
{
	JsonParser *parser;
	JsonReader *reader;
	SoupMessage *msg;
	gchar *url;
	const gchar *data;
	const gchar *port_str;
	gsize read;
	gint port;

	url = g_strdup_printf("http://%s/query.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                             "DialPort", "telcfg:settings/DialPort",
	                            NULL);
	/* Send message */
	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		g_debug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return -1;
	}

	data = msg->response_body->data;
	read = msg->response_body->length;

	//log_save_data("fritzbox-06_35-get-dial-port.html", data, read);

	parser = json_parser_new();
	json_parser_load_from_data(parser, data, read, NULL);

	reader = json_reader_new(json_parser_get_root(parser));

	json_reader_read_member(reader, "DialPort");
	port_str = json_reader_get_string_value(reader);

	port = atoi(port_str);

	g_object_unref(reader);
	g_object_unref(parser);

	return port;
}



/**
 * \brief Dial number using new ui format
 * \param profile profile information structure
 * \param port dial port
 * \param number remote number
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_dial_number_06_35(router_icl *ri, gint port, const gchar *number)
{
	SoupMessage *msg;
	gchar *port_str;
	gchar *url;
	gchar *scramble;
	gint current_port;
	gint router_port;

	/* Login to box */
  if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	current_port = fritzbox_get_dial_port(ri);
	g_debug("Current dial port: %d", current_port);

	router_port = fritzbox_get_dialport(port);

	if (port != ROUTER_DIAL_PORT_AUTO && current_port != router_port) {
		g_debug("Setting dial port %d", router_port);

		port_str = g_strdup_printf("%d", fritzbox_get_dialport(port));
		url = g_strdup_printf("http://%s/fon_num/dial_fonbook.lua", ri->host/*router_get_host(profile)*/);
		msg = soup_form_request_new(SOUP_METHOD_POST, url,
		                            "sid",ri->session_id,
		                            "clicktodial", "on",
		                            "port", port_str,
		                            "btn_apply", "",
		                            NULL);
		soup_session_send_message(soup_session, msg);
		g_free(port_str);

		current_port = fritzbox_get_dial_port(ri);
		if (current_port != router_port) {
			g_debug("Could not set dial port");
			return FALSE;
		}
	}

	/* Create GET message */
	scramble = call_scramble_number(number);
	g_debug("Call number '%s' on port %d...", scramble, current_port);
	g_free(scramble);

	url = g_strdup_printf("http://%s/fon_num/foncalls_list.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri->session_id,
	                            "dial", number,
	                            NULL);
	g_free(url);

	/* Send message */
	soup_session_send_message(soup_session, msg);
	fritzbox_logout(ri, FALSE);

	return TRUE;
}


/**
 * \brief Dial number using ClickToDial
 * \param profile profile information structure
 * \param port dial port
 * \param number remote number
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_dial_number_04_00(router_icl *ri, gint port, const gchar *number)
{
	SoupMessage *msg;
	gchar *port_str;
	gchar *scramble;
	gboolean ret = FALSE;

	/* Login to box */
  if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	/* Create POST message */
	gchar *url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	port_str = g_strdup_printf("%d", fritzbox_get_dialport(port));

	scramble = call_scramble_number(number);
	g_debug("Call number '%s' on port %s...", scramble, port_str);
	g_free(scramble);

	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "telcfg:settings/UseClickToDial", "1",
	                            "telcfg:settings/DialPort", port_str,
	                            "telcfg:command/Dial", number,
	                            "sid", ri->session_id,
	                            NULL);
	g_free(port_str);
	g_free(url);

	/* Send message */
	soup_session_send_message(soup_session, msg);
	if (msg->status_code == 200) {
		ret = TRUE;
	}
	fritzbox_logout(ri, FALSE);

	return ret;
}

/**
 * \brief Dial number using router ui
 * \param profile profile information structure
 * \param port dial port
 * \param number remote number
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_dial_number(struct router_icl *ri, gint port, const gchar *number)
{
	if (!ri) {
		return FALSE;
	}

	if (FIRMWARE_IS(6, 30)) {
		return fritzbox_dial_number_06_35(ri, port, number);
	}

	if (FIRMWARE_IS(4, 0)) {
		return fritzbox_dial_number_04_00(ri, port, number);
	}

	return FALSE;
}

/**
 * \brief Hangup call using new ui format
 * \param profile profile information structure
 * \param port dial port
 * \param number remote number
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_hangup_06_35(struct router_icl *ri, gint port, const gchar *number)
{
	SoupMessage *msg;
	gchar *port_str;
	gchar *url;
	gchar *scramble;

	/* Login to box */
  if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	/* Create GET message */
	port_str = g_strdup_printf("%d", fritzbox_get_dialport(port));

	scramble = call_scramble_number(number);
	g_debug("Hangup call '%s' on port %s...", scramble, port_str);
	g_free(scramble);

	url = g_strdup_printf("http://%s/fon_num/foncalls_list.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", ri/*profile->router_info*/->session_id,
	                            "hangup", "",
	                            NULL);
	g_free(url);
	g_free(port_str);

	/* Send message */
	soup_session_send_message(soup_session, msg);
	fritzbox_logout(ri, FALSE);

	return TRUE;
}

/**
 * \brief Hangup call
 * \param profile profile information structure
 * \param port dial port
 * \param number remote number
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_hangup_04_00(struct router_icl *ri, gint port, const gchar *number)
{
	SoupMessage *msg;
	gchar *port_str;

	/* Login to box */
  if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	/* Create POST message */
	gchar *url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	port_str = g_strdup_printf("%d", fritzbox_get_dialport(port));

	g_debug("Hangup on port %s...", port_str);

	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "telcfg:settings/UseClickToDial", "1",
	                            "telcfg:settings/DialPort", port_str,
	                            "telcfg:command/Hangup", number,
	                            "sid", ri/*profile->router_info*/->session_id,
	                            NULL);
	g_free(port_str);
	g_free(url);

	/* Send message */
	soup_session_send_message(soup_session, msg);
	fritzbox_logout(ri, FALSE);

	return TRUE;
}

/**
 * \brief Hangup call using router ui
 * \param profile profile information structure
 * \param port dial port
 * \param number remote number
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_hangup(struct router_icl *ri, gint port, const gchar *number)
{
	if (!ri) {
		return FALSE;
	}

	if (FIRMWARE_IS(6, 30)) {
		return fritzbox_hangup_06_35(ri, port, number);
	}

	if (FIRMWARE_IS(4, 0)) {
		return fritzbox_hangup_04_00(ri, port, number);
	}

	return FALSE;
}

/**
 * \brief Clear journal
 * \param profile profile pointer
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_clear_journal_05_50(struct router_icl *ri)
{
	SoupMessage *msg;
	gchar *url;

	/* Login to box */
  if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	url = g_strdup_printf("http://%s/fon_num/foncalls_list.lua", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "sid", ri/*profile->router_info*/->session_id,
	                            "usejournal", "on",
	                            "clear", "",
	                            "callstab", "all",
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		g_debug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}

	g_debug("Done");

	g_object_unref(msg);

	//router_logout(profile);

	return TRUE;
}

/**
 * \brief Clear journal
 * \param profile profile pointer
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_clear_journal_04_74(struct router_icl *ri)
{
	SoupMessage *msg;
	gchar *url;

	/* Login to box */
  if (!fritzbox_login(ri)/*router_login(profile)*/) {
		return FALSE;
	}

	url = g_strdup_printf("http://%s/cgi-bin/webcm", ri->host/*router_get_host(profile)*/);
	msg = soup_form_request_new(SOUP_METHOD_POST, url,
	                            "sid", ri/*profile->router_info*/->session_id,
	                            "getpage", "../html/de/menus/menu2.html",
	                            "var:pagename", "foncalls",
	                            "var:menu", "fon",
	                            "telcfg:settings/ClearJournal", "",
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
		g_debug("Received status code: %d", msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}

	g_debug("Done");

	g_object_unref(msg);

	fritzbox_logout(ri, FALSE);

	return TRUE;
}

/**
 * \brief Main clear journal function (big switch for each supported router)
 * \param profile profile info structure
 * \return error code
 */
gboolean fritzbox_clear_journal(struct router_icl *ri)
{
  printf("fritzbox_clear_journal\n");
	if (!ri) {
		return FALSE;
	}

	if (FIRMWARE_IS(5, 50)) {
		return fritzbox_clear_journal_05_50(ri/*profile*/);
	}

	if (FIRMWARE_IS(4, 0)) {
		return fritzbox_clear_journal_04_74(ri/*profile*/);
	}

	return FALSE;
}

/**
 * \brief Load fax file via FTP
 * \param profile profile structure
 * \param filename fax filename
 * \param len pointer to store the data length to
 * \return fax data
 */
gchar *fritzbox_load_fax(struct router_icl *ri, const gchar *filename, gsize *len)
{
	struct ftp *client;
	//gchar *user = router_get_ftp_user(profile);
	gchar *ret;

	client = ftp_init(ri->host/*router_get_host(profile)*/);
	ftp_login(client, ri->ftpusr, ri->ftppwd/*router_get_ftp_password(profile)*/);

	ftp_passive(client);

	ret = ftp_get_file(client, filename, len);
	ftp_shutdown(client);

	return ret;
}

/**
 * \brief Load voice file via FTP
 * \param profile profile structure
 * \param name voice filename
 * \param len pointer to store the data length to
 * \return voice data
 */
gchar *fritzbox_load_voice(struct router_icl *ri, const gchar *name, gsize *len)
{
	struct ftp *client;
	gchar *filename = g_strconcat("/", ri->faxvolume/*g_settings_get_string(profile->settings, "fax-volume")*/, "/FRITZ/voicebox/rec/", name, NULL);
	//gchar *user = router_get_ftp_user(profile);
	gchar *ret = NULL;

	client = ftp_init(ri->host/*router_get_host(profile)*/);
	if (!client) {
		g_debug("Could not init ftp connection");
		return ret;
	}

	ftp_login(client, ri->ftpusr, ri->ftppwd/*router_get_ftp_password(profile)*/);

	ftp_passive(client);

	ret = ftp_get_file(client, filename, len);

	ftp_shutdown(client);

	g_free(filename);

	return ret;
}

/**
 * \brief Extract IP address from router
 * \param profile profile pointer
 * \return current IP address or NULL on error
 */
gchar *fritzbox_get_ip(struct router_icl *ri)
{
	SoupMessage *msg;
	SoupURI *uri;
	gchar *ip = NULL;
	gchar *request;
	SoupMessageHeaders *headers;
	gchar *url;

	/* Create POST message */
	if (FIRMWARE_IS(6, 6)) {
		url = g_strdup_printf("http://%s/igdupnp/control/WANIPConn1", ri->host/*router_get_host(profile)*/);
	} else {
		url = g_strdup_printf("http://%s/upnp/control/WANIPConn1", ri->host/*router_get_host(profile)*/);
	}

	uri = soup_uri_new(url);
	soup_uri_set_port(uri, 49000);
	msg = soup_message_new_from_uri(SOUP_METHOD_POST, uri);
	g_free(url);

	request = g_strdup(
	              "<?xml version='1.0' encoding='utf-8'?>"
	              " <s:Envelope s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'>"
	              " <s:Body>"
	              " <u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\" />"
	              " </s:Body>"
	              " </s:Envelope>\r\n");

	soup_message_set_request(msg, "text/xml; charset=\"utf-8\"", SOUP_MEMORY_STATIC, request, strlen(request));
	headers = msg->request_headers;
	soup_message_headers_append(headers, "SoapAction", "urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress");

	soup_session_send_message(soup_session, msg);

	if (msg->status_code != 200) {
		g_debug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return NULL;
	}

	ip = xml_extract_tag(msg->response_body->data, (gchar*)"NewExternalIPAddress");

	g_object_unref(msg);

	g_debug("Got IP data (%s)", ip);

	return ip;
}


/**
 * \brief Reconnect network
 * \param profile profile pointer
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_reconnect(struct router_icl *ri)
{
	SoupMessage *msg;
	SoupURI *uri;
	gchar *request;
	SoupMessageHeaders *headers;
	gchar *url;

	/* Create POST message */
	if (FIRMWARE_IS(6, 6)) {
		url = g_strdup_printf("http://%s:49000/igdupnp/control/WANIPConn1", ri->host/*router_get_host(profile)*/);
	} else {
		url = g_strdup_printf("http://%s:49000/upnp/control/WANIPConn1", ri->host/*router_get_host(profile)*/);
	}

	uri = soup_uri_new(url);
	soup_uri_set_port(uri, 49000);
	msg = soup_message_new_from_uri(SOUP_METHOD_POST, uri);
	g_free(url);

	request = g_strdup(
	              "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
	              " <s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">"
	              " <s:Body>"
	              " <u:ForceTermination xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\" />"
	              " </s:Body>"
	              " </s:Envelope>\r\n");

	soup_message_set_request(msg, "text/xml; charset=\"utf-8\"", SOUP_MEMORY_STATIC, request, strlen(request));
	headers = msg->request_headers;
	soup_message_headers_append(headers, "SoapAction", "urn:schemas-upnp-org:service:WANIPConnection:1#ForceTermination");

	soup_session_send_message(soup_session, msg);

	if (msg->status_code != 200) {
		g_debug("%s(): Received status code: %d", __FUNCTION__, msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}

	g_object_unref(msg);

	return TRUE;
}



/**
 * \brief Delete file on FTP
 * \param client ftp client structure
 * \param filename file to delete
 * \return TRUE on success, otherwise FALSE
 */
gboolean ftp_delete_file(struct ftp *client, const gchar *filename)
{
	gchar *cmd = g_strconcat("DELE ", filename, NULL);

#ifdef FTP_DEBUG
	g_debug("ftp_delete_file(): %s", cmd);
#endif
	ftp_send_command(client, cmd);
	g_free(cmd);

	if (client->code != 250) {
		g_debug("ftp_delete_file(): code: %d", client->code);
		return FALSE;
	}

	return TRUE;
}
/**
 * \brief Delete fax file from router
 * \param profile profile pointer
 * \param filename fax filename to delete
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_delete_fax(struct router_icl *ri, const gchar *filename)
{
	struct ftp *client;
	//gchar *user = router_get_ftp_user(profile);
	gboolean ret;

	client = ftp_init(ri->host/*router_get_host(profile)*/);
	ftp_login(client, ri->ftpusr, ri->ftppwd/*router_get_ftp_password(profile)*/);

	ftp_passive(client);

	ret = ftp_delete_file(client, filename);
	ftp_shutdown(client);

	return ret;
}


/**
 * \brief Delete voice file from router
 * \param profile profile pointer
 * \param filename voice filename to delete
 * \return TRUE on success, otherwise FALSE
 */
gboolean fritzbox_delete_voice(struct router_icl *ri, const gchar *filename)
{
	struct ftp *client;
	struct voice_data *voice_data;
	gpointer modified_data;
	gint nr;
	gint count;
	gint index;
	gint offset = 0;
	gchar *name;

	nr = filename[4] - '0';
	if (!voice_boxes[nr].data || voice_boxes[nr].len == 0) {
		return FALSE;
	}

	/* Modify data */
	count = voice_boxes[nr].len / sizeof(struct voice_data);
	modified_data = g_malloc((count - 1) * sizeof(struct voice_data));

	for (index = 0; index < count; index++) {
		voice_data = (struct voice_data *)((gchar*)voice_boxes[nr].data + index * sizeof(struct voice_data));
		if (strncmp(voice_data->file, filename, strlen(filename)) != 0) {
			memcpy((gchar*)modified_data + offset, (gchar*)voice_boxes[nr].data + index * sizeof(struct voice_data), sizeof(struct voice_data));
			offset += sizeof(struct voice_data);
		}
	}

	/* Write data to router */
	client = ftp_init(ri->host/*router_get_host(profile)*/);
	ftp_login(client, ri->ftpusr, ri->ftppwd/*router_get_ftp_password(profile)*/);

	gchar *path = g_build_filename(ri->faxvolume/*g_settings_get_string(profile->settings, "fax-volume")*/, "FRITZ/voicebox/", NULL);
	gchar *remote_file = g_strdup_printf("meta%d", nr);
	if (!ftp_put_file(client, remote_file, path, (gchar*)modified_data, offset)) {
		g_free(modified_data);
		g_free(remote_file);
		g_free(path);
		ftp_shutdown(client);
		return FALSE;
	}

	g_free(remote_file);
	g_free(path);

	/* Modify internal data structure */
	g_free(voice_boxes[nr].data);
	voice_boxes[nr].data = modified_data;
	voice_boxes[nr].len = offset;

	/* Delete voice file */
	name = g_build_filename(ri->faxvolume/*g_settings_get_string(profile->settings, "fax-volume")*/, "FRITZ/voicebox/rec", filename, NULL);
	if (!ftp_delete_file(client, name)) {
		g_free(name);
		ftp_shutdown(client);
		return FALSE;
	}

	ftp_shutdown(client);

	g_free(name);

	return TRUE;
}

/** FRITZ!Box router functions */
static struct hrouter fritzbox = {
	"FRITZ!Box",
	fritzbox_present,
	fritzbox_login,
	fritzbox_logout,
	fritzbox_get_settings,
	fritzbox_load_journal,
	fritzbox_clear_journal,
	fritzbox_dial_number,
	fritzbox_hangup,
	fritzbox_load_fax,
	fritzbox_load_voice,
	fritzbox_get_ip,
	fritzbox_reconnect,
	fritzbox_delete_fax,
	fritzbox_delete_voice,
};

/**
 * \brief Register new router
 * \param router new router structure
 */
gboolean routermanager_router_register(struct hrouter *router)
{
	router_list = g_slist_prepend(router_list, router);

	return TRUE;
}

/**
 * \brief Activate plugin (register fritzbox router)
 * \param plugin peas plugin
 */
static void impl_activate(PeasActivatable *plugin)
{
	/* Register router structure */
	routermanager_router_register(&fritzbox);
}

/**
 * \brief Deactivate plugin
 * \param plugin peas plugin
 */
static void impl_deactivate(PeasActivatable *plugin)
{
	/* Currently does nothing */
}

/**
 * \brief Dial number
 * \param profile profile information structure
 * \param port dial port
 * \param number number to dial
 * \return return state of dial function
 */
gboolean router_dial_number(router_icl *ri, gint port, const gchar *number)
{
	gchar *target = call_canonize_number(ri,number);
	gboolean ret;

	ret = fritzbox_dial_number(ri, port, target);
	g_free(target);

	return ret;
}

// faxophone.c
#ifndef WIN32
#include <sys/resource.h>
#endif

// #include <libroutermanager/appobject-emit.h>

// #include <libroutermanager/libfaxophone/fax.h>
#include <libroutermanager/libfaxophone/sff.h>
#include <libroutermanager/libfaxophone/phone.h>
#include <libroutermanager/libfaxophone/isdn-convert.h>

//#define FAXOPHONE_DEBUG 1

/** The current active session */
// static struct session *session = NULL;
/** Unique connection id */
static unsigned int id = 0;
/** capi thread pointer */
static GThread *capi_thread = NULL;
/** quit capi loop thread flag */
static unsigned char faxophone_quit = 1;

/**
 * \brief Dump capi error (UNUSED)
 * \param error capi error number
 */
static void capi_error(long error)
{
	if (error != 0) {
		g_debug("->Error: 0x%lX", error);
		if (error == 0x3301) {
			g_warning("Protocol Error Layer 1");
		} else if (error == 0x2001) {
			g_warning("Message not supported in current state");
		}
		if (session) {
			session->handlers->status(NULL, error);
		}
	}
}

/**
 * \brief Set connection type, transfer and cleanup routine, b3 informations
 * \param connection capi connection
 * \param type connection type
 * \return error code: 0 on success, otherwise error
 */
static int capi_connection_set_type(struct capi_connection *connection, int type)
{
	int result = 0;

	/* Set type */
	connection->type = (session_type)type;

	/* Set informations depending on type */
	switch (type) {
	case SESSION_PHONE:
		connection->init_data = phone_init_data;
		connection->data = phone_transfer;
		connection->clean = NULL;
		connection->early_b3 = 1;
		break;
	case SESSION_FAX:
		connection->init_data = NULL;
		connection->data = fax_transfer;
		connection->clean = fax_clean;
		connection->early_b3 = 0;
		break;
	case SESSION_SFF:
		connection->init_data = sff_init_data;
		connection->data = NULL;
		connection->clean = sff_clean;
		connection->early_b3 = 0;
		break;
	default:
		g_debug("Unhandled session type!!");
		result = -1;
		break;
	}

	return result;
}

/**
 * \brief Return free capi connection index
 * \return free connection index or -1 on error
 */
struct capi_connection *capi_get_free_connection(void)
{
	int i;

	if (!session) {
		return NULL;
	}

	for (i = 0; i < CAPI_CONNECTIONS; i++) {
		if (session->connection[i].plci == 0 && session->connection[i].ncci == 0) {
			session->connection[i].id = id++;
			session->connection[i].state = STATE_IDLE;
			return &session->connection[i];
		}
	}

	return NULL;
}

/**
 * \brief Free capi connection
 * \param connection capi connection
 * \return error code
 */
static int capi_set_free(struct capi_connection *connection)
{
	/* reset connection */
	if (connection->priv != NULL) {
		if (connection->clean) {
			connection->clean(connection);
		} else {
			g_debug("Warning: Private data but no clean function");
		}
	}

	memset(connection, 0, sizeof(struct capi_connection));

	return 0;
}

/**
 * \brief Terminate selected connection
 * \param connection connection we want to terminate
 */
void capi_hangup(struct capi_connection *connection)
{
	_cmsg cmsg1;
	guint info = 0;

	if (connection == NULL) {
		return;
	}

	switch (connection->state) {
	case STATE_CONNECT_WAIT:
	case STATE_CONNECT_ACTIVE:
	case STATE_DISCONNECT_B3_REQ:
	case STATE_DISCONNECT_B3_WAIT:
	case STATE_DISCONNECT_ACTIVE:
	case STATE_INCOMING_WAIT:
		g_debug("REQ: DISCONNECT - plci %ld", connection->plci);

		isdn_lock();
		info = DISCONNECT_REQ(&cmsg1, session->appl_id, 1, connection->plci, NULL, NULL, NULL, NULL);
		isdn_unlock();

		if (info != 0) {
			connection->state = STATE_IDLE;
			session->handlers->status(connection, info);
		} else {
			connection->state = STATE_DISCONNECT_ACTIVE;
		}
		break;
	case STATE_CONNECT_B3_WAIT:
	case STATE_CONNECTED:
		g_debug("REQ: DISCONNECT_B3 - ncci %ld", connection->ncci);

		isdn_lock();
		info = DISCONNECT_B3_REQ(&cmsg1, session->appl_id, 1, connection->ncci, NULL);
		isdn_unlock();

		if (info != 0) {
			/* retry with disconnect on whole connection */
			isdn_lock();
			info = DISCONNECT_REQ(&cmsg1, session->appl_id, 1, connection->plci, NULL, NULL, NULL, NULL);
			isdn_unlock();
			if (info != 0) {
				connection->state = STATE_IDLE;
				session->handlers->status(connection, info);
			} else {
				connection->state = STATE_DISCONNECT_ACTIVE;
			}
		} else {
			connection->state = STATE_DISCONNECT_B3_REQ;
		}
		break;
	case STATE_RINGING:
		/* reject the call */
		g_debug("RESP: CONNECT - plci %ld", connection->plci);

		isdn_lock();
		info = CONNECT_RESP(&cmsg1, session->appl_id, session->message_number++, connection->plci, 3, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		isdn_unlock();
		connection->state = STATE_IDLE;
		if (info != 0) {
			session->handlers->status(connection, info);
		}

		break;
	case STATE_IDLE:
		break;
	default:
		g_debug("Unexpected state 0x%x on disconnect", connection->state);
		break;
	}
}

/**
 * \brief Call number from target using CIP value
 * \param controller controller id
 * \param src_no source number
 * \param trg_no target number
 * \param call_anonymous call anonymous flag
 * \param type connection type
 * \param cip caller id
 * \return error code
 */
struct capi_connection *capi_call(
	unsigned controller,
	const char *src_no,
	const char *trg_no,
	unsigned call_anonymous,
	unsigned type,
	unsigned cip,
	_cword b1_protocol,
	_cword b2_protocol,
	_cword b3_protocol,
	_cstruct b1_configuration,
	_cstruct b2_configuration,
	_cstruct b3_configuration)
{
	_cmsg cmsg;
	unsigned char called_party_number[70];
	unsigned char calling_party_number[70];
	unsigned char bc[4];
	unsigned char llc[3];
	unsigned char hlc[3];
	struct capi_connection *connection = NULL;
	int err = 0;
	int intern = (trg_no[0] == '*') || (trg_no[0] == '#');

	if (!session) {
		return NULL;
	}

	if (src_no == NULL || strlen(src_no) < 1 || trg_no == NULL || strlen(trg_no) < 1) {
		g_debug("Wrong phone numbers!");
		return connection;
	}

	/* Say hello */
	g_debug("REQ: CONNECT (%s->%s)", src_no, trg_no);

	/* get free connection */
	connection = capi_get_free_connection();
	if (connection == NULL) {
		return connection;
	}

	/* set connection type */
	capi_connection_set_type(connection, type);

	/* TargetNo */
	called_party_number[0] = 1 + strlen(trg_no);
	called_party_number[1] = 0x80;
	strncpy((char *) &called_party_number[2], trg_no, sizeof(called_party_number) - 3);

	/* MSN */
	calling_party_number[1] = 0x00;
	calling_party_number[2] = 0x80;

	if (call_anonymous) {
		calling_party_number[2] = 0xA0;
	}

	if (intern) {
		calling_party_number[0] = 2 + 5;
		strncpy((char *) &calling_party_number[3], "**981", sizeof(calling_party_number) - 4);

		strncpy((char *) bc, "\x03\xE0\x90\xA3", sizeof(bc));
	} else {
		calling_party_number[0] = 2 + strlen(src_no);
		strncpy((char *) &calling_party_number[3], src_no, sizeof(calling_party_number) - 4);

		memset(bc, 0, sizeof(bc));
	}
	strncpy((char *) llc, "\x02\x80\x90", sizeof(llc));

	if (cip == 0x04) {
		strncpy((char *) hlc, "\x02\x91\x81", sizeof(hlc));
	} else if (cip == 0x11) {
		//strncpy((char *) hlc, "\x02\x91\x84", sizeof(hlc));
		//strncpy((char *) bc, "\x03\x90\x90\xA3", sizeof(bc));
		memset(bc, 0, sizeof(bc));
		memset(llc, 0, sizeof(llc));
		memset(hlc, 0, sizeof(hlc));
	}

	/* Request connect */
	isdn_lock();
	err = CONNECT_REQ(
			/* CAPI Message */
			&cmsg,
			/* Application ID */
			session->appl_id,
			/* Message Number */
			0,
			/* Controller */
			controller,
			/* CIP (Voice/Fax/...) */
			cip,
			/* Called party number */
			(unsigned char *) called_party_number,
			/* Calling party number */
			(unsigned char *) calling_party_number,
			/* NULL */
			NULL,
			/* NULL */
			NULL,
			/* B1 Protocol */
			b1_protocol,
			/* B2 Protocol */
			b2_protocol,
			/* B3 Protocol */
			b3_protocol,
			/* B1 Configuration */
			b1_configuration,
			/* B2 Confguration */
			b2_configuration,
			/* B3 Configuration */
			b3_configuration,
			/* Rest... */
			NULL,
			/* BC */
			(unsigned char *) bc,
			/* LLC */
			(unsigned char *) llc,
			/* HLC */
			(unsigned char *) hlc,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL);
	isdn_unlock();

	/* Error? */
	if (err) {
		g_debug("(%d) Unable to send CONNECT_REQ!", err);
		capi_error(err);
		capi_set_free(connection);
		connection = NULL;
		return connection;
	}

	connection->target = strdup(trg_no);
	connection->source = strdup(src_no);

	return connection;
}

/**
 * \brief Pickup an incoming call
 * \param connection incoming capi connection
 * \param type handle connection as this type
 * \return error code: 0 on success, otherwise error
 */
int capi_pickup(struct capi_connection *connection, int type)
{
	_cmsg message;
	unsigned char local_num[4];
	struct session *session = faxophone_get_session();

	capi_connection_set_type(connection, type);

	if (connection->state != STATE_RINGING) {
		g_debug("CAPI Pickup called, even if not ringing");
		return -1;
	} else {
		local_num[0] = 0x00;
		local_num[1] = 0x00;
		local_num[2] = 0x00;
		local_num[3] = 0x00;

		isdn_lock();
		g_debug("RESP: CAPI_CONNECT_RESP - plci %ld", connection->plci);
		CONNECT_RESP(&message, session->appl_id, session->message_number++, connection->plci, 0, 1, 1, 0, 0, 0, 0, &local_num[0], NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		isdn_unlock();

		/* connection initiated, wait for CONNECT_ACTIVE_IND */
		connection->state = STATE_INCOMING_WAIT;
	}

	return 0;
}

/**
 * \brief Get the calling party number on CAPI_CONNECT
 * \param cmsg CAPI message
 * \param number buffer to store number
 */
static void capi_get_source_no(_cmsg *cmsg, char number[256])
{
	unsigned char *pnX = CONNECT_IND_CALLINGPARTYNUMBER(cmsg);
	unsigned int len = 0;

	memset(number, 0, 256);

	if (pnX == NULL) {
		pnX = INFO_IND_INFOELEMENT(cmsg);

		if (pnX != NULL) {
			len = (int) pnX[0];
		}
	} else {
		len = *CONNECT_IND_CALLINGPARTYNUMBER(cmsg);
	}

	if (len <= 1) {
		strcpy(number, "unknown");
	} else {
		if (len > 256) {
			len = 256 - 1;
		}

		/*switch (pnX[1] & 112) {
			case 32:
				strcat(number, getLineAccesscode());
				break;
			case 64:
				strcat(number, getLineAccesscode());
				strcat(number, getAreacode());
				break;
		}*/

		/* get number */
		if (pnX[2] & 128) {
			number[strlen(number) + pnX[0] - 1] = 0;
			number[strlen(number) + pnX[0] - 2] = 0;

			memcpy(number + strlen(number), pnX + 3, (size_t)(pnX[0] - 2));
		} else {
			number[strlen(number) + pnX[0]] = 0;
			number[strlen(number) + pnX[0] - 1] = 0;
			memcpy(number + strlen(number), pnX + 2, (size_t)(pnX[0] - 1));
		}
	}

	if (!strlen(number)) {
		strcpy(number, "anonymous");
	}
}

/**
 * \brief Get the called party number on CAPI_CONNECT
 * \param cmsg CAPI message
 * \param number buffer to store number
 */
static void capi_get_target_no(_cmsg *cmsg, char number[256])
{
	unsigned char *x = CONNECT_IND_CALLEDPARTYNUMBER(cmsg);
	unsigned int len = 0;

	memset(number, 0, 256);

	if (x == NULL) {
		x = INFO_IND_INFOELEMENT(cmsg);
		if (x != NULL) {
			len = (int) x[0];
		}
	} else {
		len = *CONNECT_IND_CALLEDPARTYNUMBER(cmsg);

		if (CONNECT_IND_CALLEDPARTYNUMBER(cmsg)[0] == 0) {
			len = 0;
		}
	}

	if (len <= 1) {
		strcpy(number, "unknown");
	} else {
		if (len > 256) {
			len = 256 - 1;
		}

		/* get number */
		/*if (strncmp((char *) x + 2, getCountrycode(), 2) == 0) {
			number[strlen(number) + (size_t) x[0]] = 0;
			number[strlen(number) + (size_t) x[0] - 1] = 0;
			strcpy(number, "0");
			memcpy(number + 1, x + 2 + 2, len - 3);
		} else*/ {
			number[strlen(number) + (size_t) x[0]] = 0;
			number[strlen(number) + (size_t) x[0] - 1] = 0;
			memcpy(number + strlen(number), x + 2, (size_t)(x[0] - 1));
		}
	}

	if (!strlen(number)) {
		strcpy(number, "anonymous");
	}
}

/**
 * \brief Find capi connection by PLCI
 * \param plci plci
 * \return capi connection or NULL on error
 */
static struct capi_connection *capi_find_plci(int plci)
{
	int index;

	for (index = 0; index < CAPI_CONNECTIONS; index++) {
		if (session->connection[index].plci == plci) {
			return &session->connection[index];
		}
	}

	return NULL;
}

/**
 * \brief Find newly created capi connection
 * \return capi connection or NULL on error
 */
static struct capi_connection *capi_find_new(void)
{
	int index;

	for (index = 0; index < CAPI_CONNECTIONS; index++) {
		if (session->connection[index].plci == 0 && session->connection[index].type != 0) {
			return &session->connection[index];
		}
	}

	return NULL;
}

/**
 * \brief Find capi connection by NCCI
 * \param ncci ncci
 * \return capi connection or NULL on error
 */
static struct capi_connection *capi_find_ncci(int ncci)
{
	int index;

	for (index = 0; index < CAPI_CONNECTIONS; index++) {
		if (session->connection[index].ncci == ncci) {
			return &session->connection[index];
		}
	}

	return NULL;
}

/**
 * \brief Close capi
 * \return error code
 */
static int capi_close(void)
{
	int index;

	if (session != NULL && session->appl_id != -1) {
		for (index = 0; index < CAPI_CONNECTIONS; index++) {
			if (session->connection[index].plci != 0 || session->connection[index].ncci != 0) {
				capi_hangup(&session->connection[index]);
				g_usleep(25);
			}
		}

		CAPI20_RELEASE(session->appl_id);
		session->appl_id = -1;
	}

	return 0;
}

/**
 * \brief CAPI respond connection
 * \param plci plci
 * \param nIgnore ignore connection
 */
static void capi_resp_connection(int plci, unsigned int ignore)
{
	_cmsg cmsg1;

	if (!ignore) {
		/* *ring* */
		g_debug("REQ: ALERT - plci %d", plci);
		isdn_lock();
		ALERT_REQ(&cmsg1, session->appl_id, 0, plci, NULL, NULL, NULL, NULL, NULL);
		isdn_unlock();
	} else {
		/* ignore */
		isdn_lock();
		CONNECT_RESP(&cmsg1, session->appl_id, session->message_number++, plci, ignore, 1, 1, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		isdn_unlock();
	}
}

/**
 * \brief Enable DTMF support.
 * \param isdn isdn device structure.
 * \param ncci NCCI
 */
static void capi_enable_dtmf(struct capi_connection *connection)
{
	_cmsg message;
	_cbyte facility[11];

	/* Message length */
	facility[0] = 10;
	/* DTMF ON: 0x01, DTMF OFF: 0x02 */
	facility[1] = (_cbyte) 0x01;
	/* NULL */
	facility[2] = 0x00;
	/* DTMF Duration */
	facility[3] = 0x40;
	/* NULL */
	facility[4] = 0x00;
	/* DTMF Duration */
	facility[5] = 0x40;
	/* NULL */
	facility[6] = 0x00;
	/* NULL */
	facility[7] = 0x00;
	/* 2 */
	facility[8] = 0x02;
	/* NULL */
	facility[9] = 0x00;
	/* NULL */
	facility[10] = 0x00;

	g_debug("Enable DTMF for PLCI %ld", connection->plci);

	/* 0x01 = DTMF selector */
	isdn_lock();
	FACILITY_REQ(&message, session->appl_id, 0/*isdn->message_number++*/, connection->plci, 0x01, (unsigned char *) facility);
	isdn_unlock();
}

/**
 * \brief Signal DTMF code to application
 * \param connection active capi connection
 * \param dtmf DTMF code
 */
static void capi_get_dtmf_code(struct capi_connection *connection, unsigned char dtmf)
{
	if (dtmf == 0) {
		return;
	}

	if (!isdigit(dtmf)) {
		if (dtmf != '#' && dtmf != '*') {
			return;
		}
	}

	session->handlers->code(connection, dtmf);
}

/**
 * \brief Send DTMF to remote
 * \param connection active capi connection
 * \param dtmf DTMF code we want to send
 */
void capi_send_dtmf_code(struct capi_connection *connection, unsigned char dtmf)
{
	_cmsg message;
	_cbyte facility[32];

	g_debug("dtmf: %c", dtmf);

	/* Message length */
	facility[0] = 0x08;
	/* Send DTMF 0x03 */
	facility[1] = (_cbyte) 0x03;
	/* NULL */
	facility[2] = 0x00;
	/* DTMF Duration */
	facility[3] = 0x30;
	/* NULL */
	facility[4] = 0x00;
	/* DTMF Duration */
	facility[5] = 0x30;
	/* NULL */
	facility[6] = 0x00;
	/* NULL */
	facility[7] = 0x01;
	/* NULL */
	facility[8] = dtmf;

	g_debug("Sending DTMF code for NCCI %ld", connection->ncci);

	/* 0x01 = DTMF selector */
	isdn_lock();
	FACILITY_REQ(&message, session->appl_id, 0/*isdn->message_number++*/, connection->ncci, 0x01, (unsigned char *) facility);
	isdn_unlock();
}

/**
 * \brief Send display message to remote
 * \param connection active capi connection
 * \param pnDtmf text we want to send
 */
void capi_send_display_message(struct capi_connection *connection, char *text)
{
	_cmsg message;
	_cbyte facility[62 + 3];
	int len = 31;

	g_debug("Sending text: '%s'", text);
	memset(facility, 0, sizeof(facility));

	if (strlen(text) < 31) {
		len = strlen(text);
	}

	/* Complete length */
	facility[0] = len + 2;
	/* Send DTMF 0x03 */
	facility[1] = (_cbyte) 0x28;
	/* Message length */
	facility[0] = len;

	strncpy((char *) facility + 3, text, len);

	isdn_lock();
	INFO_REQ(&message, session->appl_id, 0, connection->plci, (unsigned char *) "", (unsigned char *) "", (unsigned char *) "", (unsigned char *) "", (unsigned char *) facility, NULL);
	isdn_unlock();
}

/**
 * \brief Workaround for spandsp tx problem
 * \param connection capi connection
 */
void fax_spandsp_workaround(struct capi_connection *connection)
{
	struct fax_status *status = (fax_status*)connection->priv;
	gint index;

	if (status->phase < PHASE_E) {
		g_debug("Spandsp is not yet completed - give it a little more time...");

		for (index = 0; index < 32768; index++) {
			uint8_t buf[CAPI_PACKETS];

			memset(buf, 128, CAPI_PACKETS);
			spandsp_rx(status->fax_state, buf, CAPI_PACKETS);
			spandsp_tx(status->fax_state, buf, CAPI_PACKETS);

			if (status->phase >= PHASE_E) {
				return;
			}
		}

		g_debug("Workaround failed, phase is still: %d", status->phase);
	}
}

/**
 * \brief CAPI indication
 * \param capi_message capi message structure
 * \return error code
 */
static int capi_indication(_cmsg capi_message)
{
	_cmsg cmsg1;
	int plci = -1;
	int ncci = -1;
	char source_phone_number[256];
	char target_phone_number[256];
	int cip = -1;
	struct capi_connection *connection = NULL;
	int reject = 0;
	int info;
	char info_element[128];
	int index;
	int nTmp;

	switch (capi_message.Command) {
	case CAPI_CONNECT:
		/* CAPI_CONNECT - Connect indication when called from remote phone */
		plci = CONNECT_IND_PLCI(&capi_message);
		cip = CONNECT_IND_CIPVALUE(&capi_message);

		capi_get_source_no(&capi_message, source_phone_number);
		capi_get_target_no(&capi_message, target_phone_number);

		g_debug("IND: CAPI_CONNECT - plci %d, source %s, target %s, cip: %d", plci, (source_phone_number), (target_phone_number), cip);

		reject = 0;

		if (cip != 16 && cip != 1 && cip != 4 && cip != 17) {
			/* not telephony nor fax, ignore */
			reject = 1;
		}

#ifdef ACCEPT_INTERN
		if (reject && strncmp(source_phone_number, "**", 2)) {
#else
		if (reject) {
#endif
			/* Ignore */
			g_debug("IND: CAPI_CONNECT - plci: %d, ncci: %d - IGNORING (%s <- %s)", plci, 0, target_phone_number, source_phone_number);
			capi_resp_connection(plci, 1);
		} else {
			connection = capi_get_free_connection();

			connection->type = SESSION_NONE;
			connection->state = STATE_RINGING;
			connection->plci = plci;
			connection->source = g_strdup(source_phone_number);
			connection->target = g_strdup(target_phone_number);

			capi_resp_connection(plci, 0);

		}

		break;

	/* CAPI_CONNECT_ACTIVE - Active */
	case CAPI_CONNECT_ACTIVE:
		plci = CONNECT_ACTIVE_IND_PLCI(&capi_message);

		g_debug("IND: CAPI_CONNECT_ACTIVE - plci %d", plci);

		g_debug("RESP: CAPI_CONNECT_ACTIVE - plci %d", plci);
		isdn_lock();
		CONNECT_ACTIVE_RESP(&cmsg1, session->appl_id, session->message_number++, plci);
		isdn_unlock();

		connection = capi_find_plci(plci);
		if (connection == NULL) {
			g_debug("Wrong PLCI 0x%x", plci);
			break;
		}
		g_debug("IND: CAPI_CONNECT_ACTIVE - connection: %d, plci: %ld", connection->id, connection->plci);

		/* Request B3 when sending... */
		if (connection->state == STATE_INCOMING_WAIT) {
			connection->connect_time = time(NULL);

			connection->state = STATE_CONNECT_ACTIVE;
			if (connection->type == SESSION_PHONE) {
				connection->audio = session->handlers->audio_open();
				if (!connection->audio) {
					g_warning("Could not open audio. Hangup");
					capi_hangup(connection);
					connection->audio = NULL;
				}
			}
		} else if (connection->early_b3 == 0) {
			g_debug("REQ: CONNECT_B3 - nplci %d", plci);
			isdn_lock();
			info = CONNECT_B3_REQ(&cmsg1, session->appl_id, 0, plci, 0);
			isdn_unlock();

			if (info != 0) {
				session->handlers->status(connection, info);
				/* initiate hangup on PLCI */
				capi_hangup(connection);
			} else {
				/* wait for CONNECT_B3, then announce result to application via callback */
				connection->connect_time = time(NULL);

				connection->state = STATE_CONNECT_ACTIVE;
				if (connection->type == SESSION_PHONE) {
					connection->audio = session->handlers->audio_open();
					if (!connection->audio) {
						g_warning((gchar*)"Could not open audio. Hangup");
						emit_message(0, (gchar*)"Could not open audio. Hangup");
						capi_hangup(connection);
						connection->audio = NULL;
					}
				}
			}
		}

		break;

	/* CAPI_CONNECT_B3 - data connect */
	case CAPI_CONNECT_B3:
		g_debug("IND: CAPI_CONNECT_B3");
		ncci = CONNECT_B3_IND_NCCI(&capi_message);
		plci = ncci & 0x0000ffff;

		connection = capi_find_plci(plci);
		if (connection == NULL) {
			break;
		}

		/* Answer the info message */
		isdn_lock();
		CONNECT_B3_RESP(&cmsg1, session->appl_id, session->message_number++, ncci, 0, (_cstruct) NULL);
		isdn_unlock();

		if (connection->state == STATE_CONNECT_ACTIVE) {
			connection->ncci = ncci;
			connection->state = STATE_CONNECT_B3_WAIT;
		} else {
			/* Wrong connection state for B3 connect, trigger disconnect */
			capi_hangup(connection);
		}
		break;

	/* CAPI_CONNECT_B3_ACTIVE - data active */
	case CAPI_CONNECT_B3_ACTIVE:
		g_debug("IND: CAPI_CONNECT_B3_ACTIVE");
		ncci = CONNECT_B3_ACTIVE_IND_NCCI(&capi_message);
		plci = ncci & 0x0000ffff;

		connection = capi_find_plci(plci);
		if (connection == NULL) {
			g_debug("Wrong NCCI, got 0x%x", ncci);
			break;
		}

		connection->ncci = ncci;
		isdn_lock();
		CONNECT_B3_ACTIVE_RESP(&cmsg1, session->appl_id, session->message_number++, ncci);
		isdn_unlock();

		connection->state = STATE_CONNECTED;

		capi_enable_dtmf(connection);
		if (connection->init_data) {
			connection->init_data(connection);
		}

		/* notify application about successful call establishment */
		session->handlers->connected(connection);
		break;

	/* CAPI_DATA_B3 - data - receive/send */
	case CAPI_DATA_B3:
#ifdef FAXOPHONE_DEBUG
		g_debug("IND: CAPI_DATA_B3");
#endif
		ncci = DATA_B3_IND_NCCI(&capi_message);

		connection = capi_find_ncci(ncci);
		if (connection == NULL) {
			break;
		}

#ifdef FAXOPHONE_DEBUG
		g_debug("IND: CAPI_DATA_B3 - nConnection: %d, plci: %ld, ncci: %ld", connection->id, connection->plci, connection->ncci);
#endif
		connection->data(connection, capi_message);

		break;

	/* CAPI_FACILITY - Facility (DTMF) */
	case CAPI_FACILITY:
		g_debug("IND: CAPI_FACILITY");
		ncci = CONNECT_B3_IND_NCCI(&capi_message);
		plci = ncci & 0x0000ffff;

		isdn_lock();
		FACILITY_RESP(&cmsg1, session->appl_id, session->message_number++, plci, FACILITY_IND_FACILITYSELECTOR(&capi_message), FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message));
		isdn_unlock();

		connection = capi_find_plci(plci);
		if (connection == NULL) {
			break;
		}

		g_debug("IND: CAPI_FACILITY %d", FACILITY_IND_FACILITYSELECTOR(&capi_message));
		switch (FACILITY_IND_FACILITYSELECTOR(&capi_message)) {
		case 0x0001:
			/* DTMF */
			capi_get_dtmf_code(connection, (unsigned char) FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[1]);
			break;
		case 0x0003:
			/* Supplementary Services */
			nTmp = (unsigned int)(((unsigned int) FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[1]) | ((unsigned int) FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[3] << 8));

			g_debug("%x %x %x %x %x %x", FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[0],
			        FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[1],
			        FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[2],
			        FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[3],
			        FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[4],
			        FACILITY_IND_FACILITYINDICATIONPARAMETER(&capi_message)[5]);
			if (nTmp == 0x0203) {
				/* Retrieve */
				g_debug("FACILITY: RETRIEVE");
				isdn_lock();
				info = CONNECT_B3_REQ(&cmsg1, session->appl_id, 0, plci, 0);
				isdn_unlock();

				if (info != 0) {
					session->handlers->status(connection, info);
					/* initiate hangup on PLCI */
					capi_hangup(connection);
				} else {
					/* wait for CONNECT_B3, then announce result to application via callback */
					connection->state = STATE_CONNECT_ACTIVE;
				}
			} else if (nTmp == 0x0202) {
				/* Hold */
				g_debug("FACILITY: HOLD");
			} else {
				g_debug("FACILITY: Unknown %x", nTmp);
			}
			break;
		default:
			g_debug("Unhandled facility selector!! %x", FACILITY_IND_FACILITYSELECTOR(&capi_message));
			break;
		}
		break;

	/* CAPI_INFO */
	case CAPI_INFO:
		plci = INFO_IND_PLCI(&capi_message);
		info = INFO_IND_INFONUMBER(&capi_message);

		/* Respond to INFO */
		isdn_lock();
		INFO_RESP(&cmsg1, session->appl_id, session->message_number++, plci);
		isdn_unlock();

		memset(info_element, 0, sizeof(info_element));
		for (index = 0; index < sizeof(info_element); index++) {
			info_element[index] = INFO_IND_INFOELEMENT(&capi_message)[index];
		}

		switch (info) {
		case 0x0008:
			/* Cause */
			g_debug("CAPI_INFO - CAUSE");
			g_debug("Hangup cause: 0x%x", info_element[2] & 0x7F);
			break;
		case 0x00014:
			/* Call state */
			g_debug("CAPI_INFO - CALL STATE (0x%02x)", info_element[0]);
			break;
		case 0x0018:
			/* Channel identification */
			g_debug("CAPI_INFO - CHANNEL IDENTIFICATION (0x%02x)", info_element[0]);
			break;
		case 0x001C:
			/* Facility Q.932 */
			g_debug("CAPI_INFO - FACILITY Q.932");
			break;
		case 0x001E:
			/* Progress Indicator */
			g_debug("CAPI_INFO - PROGRESS INDICATOR (0x%02x)", info_element[0]);
			if (info_element[0] < 2) {
				g_debug("CAPI_INFO - Progress description missing");
			} else {
				switch (info_element[2] & 0x7F) {
				case 0x01:
					g_debug("CAPI_INFO - Not end-to-end ISDN");
					break;
				case 0x02:
					g_debug("CAPI_INFO - Destination is non ISDN");
					break;
				case 0x03:
					g_debug("CAPI_INFO - Origination is non ISDN");
					break;
				case 0x04:
					g_debug("CAPI_INFO - Call returned to ISDN");
					break;
				case 0x05:
					g_debug("CAPI_INFO - Interworking occurred");
					break;
				case 0x08:
					g_debug("CAPI_INFO - In-band information available");
					break;
				default:
					g_debug("CAPI_INFO - Unknown progress description 0x%02x", info_element[2]);
					break;
				}
			}
			break;
		case 0x0027:
			/* Notification Indicator */
			switch ((unsigned int) info_element[0]) {
			case 0:
				g_debug("CAPI_INFO - NI - CALL SUSPENDED (%d)", info_element[0]);
				break;
			case 1:
				g_debug("CAPI_INFO - NI - CALL RESUMED (%d)", info_element[0]);
				break;
			case 2:
				g_debug("CAPI_INFO - NI - BEARER SERVICE CHANGED (%d)", info_element[0]);
				break;
			case 0xF9:
				g_debug("CAPI_INFO - NI - PUT ON HOLD (%d)", info_element[0]);
				break;
			case 0xFA:
				g_debug("CAPI_INFO - NI - RETRIEVED FROM HOLD (%d)", info_element[0]);
				break;
			default:
				g_debug("CAPI_INFO - NI - UNKNOWN (%d)", info_element[0]);
				break;
			}
			break;
		case 0x0028:
			/* Display */
			g_debug("CAPI_INFO - DISPLAY");
			break;
		case 0x0029:
			/* DateTime */
			g_debug("CAPI_INFO - DATE/TIME (%02d/%02d/%02d %02d:%02d)",
			        info_element[0], info_element[1], info_element[2], info_element[3], info_element[4]);
			break;
		case 0x002C:
			/* Keypad facility */
			g_debug("CAPI_INFO - KEYPAD FACILITY");
			break;
		case 0x006C: {
			/* Caller party number */
			//int tmp;

			//g_debug("CAPI_INFO - CALLER PARTY NUMBER (%.%s)", info_element[0], &info_element[1]);
			g_debug("CAPI_INFO - CALLER PARTY NUMBER");

			/*for (tmp = 0; tmp < sizeof(info_element); tmp++) {
				g_debug("InfoElement (%d): %x (%c)", tmp, info_element[tmp], info_element[tmp]);
			}*/
			break;
		}
		case 0x0070:
			/* Called Party Number */
			g_debug("CAPI_INFO - CALLED PARTY NUMBER");
			break;
		case 0x0074:
			/* Redirecting Number */
			g_debug("CAPI_INFO - REDIRECTING NUMBER");
			break;
		case 0x00A1:
			/* Sending complete */
			g_debug("CAPI_INFO - SENDING COMPLETE");
			break;
		case 0x4000:
			/* Charge in Units */
			g_debug("CAPI_INFO - CHARGE IN UNITS");
			break;
		case 0x4001:
			/* Charge in Currency */
			g_debug("CAPI_INFO - CHARGE IN CURRENCY");
			break;
		case 0x8001:
			/* Alerting */
			g_debug("CAPI_INFO - ALERTING (Setup early...)");
			break;
		case 0x8002:
			/* Call Proceeding */
			g_debug("CAPI_INFO - CALL PROCEEDING");
			break;
		case 0x8003:
			/* Progress */
			g_debug("CAPI_INFO - PROGRESS (Setup early...)");
			break;
		case 0x8005:
			/* Setup */
			g_debug("CAPI_INFO - SETUP");
			break;
		case 0x8007:
			/* Connect */
			g_debug("CAPI_INFO - CONNECT");
			break;
		case 0x800D:
			/* Setup ACK */
			g_debug("CAPI_INFO - SETUP ACK");
			break;
		case 0x800F:
			/* Connect ACK */
			g_debug("CAPI_INFO - CONNECT ACK");
			break;
		case 0x8045:
			/* Disconnect */
			connection = capi_find_plci(plci);

			if (connection == NULL) {
				break;
			}
			g_debug("CAPI_INFO information indicated disconnect, so terminate connection");

			capi_hangup(connection);
			break;
		case 0x804D:
			/* Release */
			g_debug("CAPI_INFO - RELEASE");
			break;
		case 0x805A:
			/* Release Complete */
			g_debug("CAPI_INFO - RELEASE COMPLETE");
			break;
		case 0x8062:
			/* Facility */
			g_debug("CAPI_INFO - FACILITY");
			break;
		case 0x806E:
			/* Notify */
			g_debug("CAPI_INFO - NOTIFY");
			break;
		case 0x807B:
			/* Information */
			g_debug("CAPI_INFO - INFORMATION");
			break;
		case 0x807D:
			/* status */
			g_debug("CAPI_INFO - STATUS");
			break;
		default:
			/* Unknown */
			g_debug("CAPI_INFO - UNKNOWN INFO (0x%02x)", info);
			break;
		}

		connection = capi_find_plci(plci);
		if (connection != NULL) {
			if (connection->early_b3 != 0 && connection->state == STATE_CONNECT_WAIT && info == 0x001E) {
				g_debug("REQ: CONNECT_B3 - Early-B3");

				isdn_lock();
				CONNECT_B3_REQ(&cmsg1, session->appl_id, 0, plci, 0);
				isdn_unlock();

				connection->connect_time = time(NULL);
				if (connection->type == SESSION_PHONE) {
					connection->audio = session->handlers->audio_open();
					if (!connection->audio) {
						g_warning((gchar*)"Could not open audio. Hangup");
						emit_message(0, (gchar*)"Could not open audio. Hangup");
						capi_hangup(connection);
						connection->audio = NULL;
					} else {
						connection->state = STATE_CONNECT_ACTIVE;
					}
				} else {
					connection->state = STATE_CONNECT_ACTIVE;
				}
			}
		}
		break;

	/* CAPI_DISCONNECT_B3 - Disconnect data */
	case CAPI_DISCONNECT_B3:
		g_debug("IND: DISCONNECT_B3");
		ncci = DISCONNECT_B3_IND_NCCI(&capi_message);
		plci = ncci & 0x0000ffff;

		isdn_lock();
		DISCONNECT_B3_RESP(&cmsg1, session->appl_id, session->message_number++, ncci);
		isdn_unlock();

		connection = capi_find_ncci(ncci);
		if (connection == NULL) {
			break;
		}

		connection->reason_b3 = DISCONNECT_B3_IND_REASON_B3(&capi_message);
		connection->ncci = 0;
		if (connection->state == STATE_CONNECTED || connection->state == STATE_CONNECT_B3_WAIT) {
			/* passive disconnect, DISCONNECT_IND comes later */
			connection->state = STATE_DISCONNECT_ACTIVE;
		} else {
			/* active disconnect, needs to send DISCONNECT_REQ */
			capi_hangup(connection);
		}

		g_debug("IND: CAPI_DISCONNECT_B3 - connection: %d, plci: %ld, ncci: %ld", connection->id, connection->plci, connection->ncci);
		break;

	/* CAPI_DISCONNECT - Disconnect */
	case CAPI_DISCONNECT:
		plci = DISCONNECT_IND_PLCI(&capi_message);
		info = DISCONNECT_IND_REASON(&capi_message);

		g_debug("IND: DISCONNECT - plci %d", plci);

		g_debug("RESP: DISCONNECT - plci %d", plci);
		isdn_lock();
		DISCONNECT_RESP(&cmsg1, session->appl_id, session->message_number++, plci);
		isdn_unlock();

		connection = capi_find_plci(plci);
		if (connection == NULL) {
			g_debug("Connection not found, IGNORING");
			break;
		}

		/* CAPI-Error code */
		connection->reason = DISCONNECT_IND_REASON(&capi_message);
		connection->state = STATE_IDLE;
		connection->ncci = 0;
		connection->plci = 0;

		switch (connection->type) {
		case SESSION_PHONE:
			if (session->input_thread_state == 1) {
				session->input_thread_state++;
				do {
					g_usleep(10);
				} while (session->input_thread_state != 0);
			}
			session->handlers->audio_close(connection->audio);
			break;
		case SESSION_FAX:
			/* Fax workaround */
			fax_spandsp_workaround(connection);
			break;
		default:
			break;
		}

		session->handlers->disconnected(connection);

		capi_set_free(connection);
		break;
	default:
		g_debug("Unhandled command 0x%x", capi_message.Command);
		break;
	}

	return 0;
}

/**
 * \brief CAPI confirmation
 * \param capi_message capi message structure
 */
static void capi_confirmation(_cmsg capi_message)
{
	struct capi_connection *connection = NULL;
	unsigned int info;
	unsigned int plci;
	unsigned int ncci;
#ifdef FAXOPHONE_DEBUG
	int controller;
#endif

	switch (capi_message.Command) {
	case CAPI_FACILITY:
		/* Facility */
		g_debug("CNF: CAPI_FACILITY; Info: %d", capi_message.Info);
		break;
	case CAPI_LISTEN:
		/* Listen confirmation */
#ifdef FAXOPHONE_DEBUG
		controller = LISTEN_CONF_CONTROLLER(&capi_message);
		g_debug("CNF: CAPI_LISTEN: controller %d, info %d", controller, capi_message.Info);
#endif
		break;
	case CAPI_ALERT:
		/* Alert message */
		g_debug("CNF: CAPI_ALERT");
		info = ALERT_CONF_INFO(&capi_message);
		plci = ALERT_CONF_PLCI(&capi_message);

		g_debug("CNF: CAPI_ALERT: info %d, plci %d", info, plci);

		connection = capi_find_plci(plci);

		if (info != 0 && info != 3) {
			if (connection != NULL) {
				connection->state = STATE_IDLE;
			}
		} else {
			session->handlers->ring(connection);
		}
		break;
	case CAPI_DATA_B3:
		/* Sent data acknowledge, NOP */
#ifdef FAXOPHONE_DEBUG
		g_debug("CNF: DATA_B3");
#endif
		info = DATA_B3_CONF_INFO(&capi_message);
		ncci = DATA_B3_CONF_NCCI(&capi_message);

#ifdef FAXOPHONE_DEBUG
		g_debug("CNF: CAPI_ALERT: info %d, ncci %d", info, ncci);
#endif

		connection = capi_find_ncci(ncci);
		if (connection && connection->use_buffers && connection->buffers) {
			connection->buffers--;
		}
		break;
	case CAPI_INFO:
		/* Info, NOP */
		g_debug("CNF: CAPI_INFO: info %d", capi_message.Info);
		break;
	case CAPI_CONNECT:
		/* Physical channel connection is being established */
		plci = CONNECT_CONF_PLCI(&capi_message);
		info = CONNECT_CONF_INFO(&capi_message);

		g_debug("CNF: CAPI_CONNECT - (plci: %d, info: %d)", plci, info);
		/* .. or new outgoing call? get plci. */
		connection = capi_find_new();
		if (connection == NULL) {
			g_debug("CND: CAPI_CONNECT - Warning! Received confirmation but we didn't requested a connect!!!");
			break;
		}

		if (info != 0) {
			/* Connection error */
			connection->state = STATE_IDLE;

			session->handlers->status(connection, info);

			capi_set_free(connection);
		} else {
			/* CONNECT_ACTIVE_IND comes later, when connection actually established */
			connection->plci = plci;
			connection->state = STATE_CONNECT_WAIT;
		}
		break;
	case CAPI_CONNECT_B3:
		plci = CONNECT_CONF_PLCI(&capi_message);

		g_debug("CNF: CAPI_CONNECT_B3");
		capi_error(capi_message.Info);
		break;
	case CAPI_DISCONNECT:
		g_debug("CNF: CAPI_DISCONNECT");
		break;
	case CAPI_DISCONNECT_B3:
		g_debug("CNF: CAPI_DISCONNECT_B3");
		break;
	default:
		g_debug("Unhandled confirmation, command 0x%x", capi_message.Command);
		break;
	}
}

static int capi_init(int controller);

/**
 * \brief Our connection seems to be broken - reconnect
 * \param session faxophone session pointer
 * \return error code
 */
static void faxophone_reconnect(struct session *session)
{
	isdn_lock();
	capi_close();

	session->appl_id = capi_init(-1);

	isdn_unlock();
}

/**
 * \brief Main capi loop function
 * \param user_data unused pointer
 * \return NULL
 */
static gpointer capi_loop(void *user_data)
{
	struct timeval time_val;
	unsigned int info;
	unsigned int ret;
	_cmsg capi_message;

	while (!faxophone_quit) {
		time_val.tv_sec = 1;
		time_val.tv_usec = 0;

		ret = CAPI20_WaitforMessage(session->appl_id, &time_val);
		if (ret == CapiNoError) {
			isdn_lock();
			info = capi_get_cmsg(&capi_message, session->appl_id);
			isdn_unlock();

			switch (info) {
			case CapiNoError:
				switch (capi_message.Subcommand) {
				/* Indication */
				case CAPI_IND:
					capi_indication(capi_message);
					break;
				/* Confirmation */
				case CAPI_CONF:
					capi_confirmation(capi_message);
					break;
				}
				break;
			case CapiReceiveQueueEmpty:
				g_warning("Empty queue, even if message pending.. reconnecting");
				g_usleep(1 * G_USEC_PER_SEC);
				faxophone_reconnect(session);
				break;
			default:
				return NULL;
			}
		} else if (!faxophone_quit) {
			if (session == NULL || session->appl_id == -1) {
				g_usleep(1 * G_USEC_PER_SEC);
			} else {
				g_usleep(1);
			}
		}
	}

	session = NULL;

	return NULL;
}

/**
 * \brief get capi profile
 * Convert capi_profile data from wire format to host format
 * \param Controller capi controller
 * \param host host formated capi profile pointer
 * \return error code
 */
static int get_capi_profile(unsigned controller, struct capi_profile *host)
{
	int ret_val = CAPI20_GET_PROFILE(controller, (unsigned char *) host);

	if (ret_val == 0) {
	}

	return ret_val;
}

/**
 * \brief Initialize CAPI controller
 * \param controller controller id
 * \return error code
 */
static int capi_init(int controller)
{
	CAPI_REGISTER_ERROR error_code = 0;
	_cmsg capi_message;
	unsigned int appl_id = -1;
#ifdef FAXOPHONE_DEBUG
	unsigned char buffer[64];
#endif
	int index;
	int start = 0;
	int end = 0;
	int num_controllers = 0;
	struct capi_profile profile;

	/* Check if capi is installed */
	error_code = CAPI20_ISINSTALLED();
	if (error_code != 0) {
		g_warning("CAPI 2.0: not installed, RC=0x%x", error_code);
		return -1;
	}

	/* Fetch controller/bchannel count */
	error_code = get_capi_profile(0, &profile);
	if (error_code != 0) {
		g_warning("CAPI 2.0: Error getting profile, RC=0x%x", error_code);
		return -1;
	}

	/* If there are no available controllers something went wrong, abort */
	num_controllers = profile.ncontroller;
	if (num_controllers == 0) {
		g_warning("CAPI 2.0: No ISDN controllers installed");
		return -1;
	}

#ifdef FAXOPHONE_DEBUG
	for (index = 1; index <= num_controllers; index++) {
		get_capi_profile(index, &profile);

		g_debug("CAPI 2.0: Controller: %d, Options: 0x%x", index, profile.goptions);

		int channels = profile.nbchannel;
		int dtmf = profile.goptions & 0x08 ? 1 : 0;
		int supp_serv = profile.goptions & 0x10;
		int echo = profile.goptions & 0x200;
		int intern = profile.goptions & 0x01;
		int extrn = profile.goptions & 0x02;
		int transp;
		int fax;
		int fax_ext;

		if (profile.support1 & 0x02 && profile.support2 & 0x02 && profile.support3 & 0x01) {
			transp = 1;
		} else {
			transp = 0;
		}

		if (profile.support1 & 0x10 && profile.support2 & 0x10 && profile.support3 & 0x10) {
			fax = 1;
		} else {
			fax = 0;
		}

		if (profile.support1 & 0x10 && profile.support2 & 0x10 && profile.support3 & 0x20) {
			fax_ext = 1;
		} else {
			fax_ext = 0;
		}

		g_debug("CAPI 2.0: B-Channels %d, DTMF %d, FAX %d/%d, Transp %d, SuppServ %d",
            channels, dtmf, fax, fax_ext, transp, supp_serv);
		g_debug("CAPI 2.0: Echo: %d, Intern: %d, extrn: %d", echo, intern, extrn);

		//pnManu = ( unsigned char * ) profile.manu;

		//opDebug( FOP_DEBUG, "manufactor profile: 0x%x, 0x%x, 0x%x, 0x%x\n", pnManu[0], pnManu[1], pnManu[2], pnManu[3]);
		//FopDebug( FOP_DEBUG, "Found nController #%d with %d B-channel(s)\n", nIndex, profile.nbchannel );

		g_debug("CAPI 2.0: B1 support = 0x%x", profile.support1);
		g_debug("CAPI 2.0: B2 support = 0x%x", profile.support2);
		g_debug("CAPI 2.0: B3 support = 0x%x", profile.support3);
	}

	/* Read manufacturer and version from device (entry 0) */
	g_debug("CAPI 2.0: Controllers found: %d", num_controllers);
	if (capi20_get_manufacturer(0, buffer)) {
		g_debug("CAPI 2.0: Manufacturer: %s", buffer);
	}
	if (capi20_get_version(0, buffer)) {
		g_debug("CAPI 2.0: Version %d.%d/%d.%d",
		        buffer[0], buffer[1], buffer[2], buffer[3]);
	}
#endif

	/* Listen to all (<=0) or single controller (>=1) */
	if (controller <= 0) {
		start = 1;
		end = num_controllers;
	} else {
		start = controller;
		end = controller;
	}

	/* Register with CAPI */
	if (appl_id == -1) {
		error_code = CAPI20_REGISTER(CAPI_BCHANNELS, CAPI_BUFFERCNT, CAPI_PACKETS, &appl_id);
		if (error_code != 0 || appl_id == 0) {
			g_debug("Error while registering application, RC=0x%x", error_code);
			/* registration error! */
			return -2;
		}
	}

	/* Listen to CAPI controller(s) */
	for (index = start; index <= end; index++) {
		error_code = LISTEN_REQ(&capi_message, appl_id, 0, index, 0x3FF, 0x1FFF03FF, 0, NULL, NULL);
		if (error_code != 0) {
			g_debug("LISTEN_REQ failed, RC=0x%x", error_code);
			return -3;
		}

		g_debug("Listen to controller #%d ...", index);
#ifdef FAXOPHONE_DEBUG
		g_debug("Listen to controller #%d ...", index);
#endif
	}

	g_debug("CAPI connection established!");

	/* ok! */
	return appl_id;
}

void setHostName(const char *);

/**
 * \brief Get sign and magnitude
 * \param sample alaw sample
 * \param sign sign
 * \param mag magnitude
 */
static inline void alaw_get_sign_mag(short sample, unsigned *sign, unsigned *mag)
{
	if (sample < 0) {
		*mag = -sample;
		*sign = 0;
	} else {
		*mag = sample;
		*sign = 0x80;
	}
}

static unsigned char linear2alaw(short sample)
{
	unsigned sign, exponent, mantissa, mag;
	unsigned char alaw_byte;
	static const unsigned exp_lut[128] = {
		1, 1, 2, 2, 3, 3, 3, 3,
		4, 4, 4, 4, 4, 4, 4, 4,
		5, 5, 5, 5, 5, 5, 5, 5,
		5, 5, 5, 5, 5, 5, 5, 5,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7
	};

	alaw_get_sign_mag(sample, &sign, &mag);
	if (mag > 32767) {
		mag = 32767;
	}

	exponent = exp_lut[(mag >> 8) & 0x7F];
	mantissa = (mag >> (exponent + 3)) & 0x0F;

	if (mag < 0x100) {
		exponent = 0;
	}

	alaw_byte = (unsigned char)(sign | (exponent << 4) | mantissa);
	alaw_byte ^= 0x55;

	return alaw_byte;
}

/**
 * \brief Convert alaw value to linear value
 * \param alaw_byte alaw value
 * \return linear value
 */
static short alaw2linear(unsigned char alaw_byte)
{
	int t;
	int seg;

	alaw_byte ^= 0x55;
	t = alaw_byte & 0x7F;

	if (t < 16) {
		t = (t << 4) + 8;
	} else {
		seg = (t >> 4) & 0x07;
		t = ((t & 0x0F) << 4) + 0x108;
		t <<= seg - 1;
	}

	return ((alaw_byte & 0x80) ? t : - t);
}

/**
 * \brief Create lookup table buffer
 */
void create_table_buffer(void)
{
	signed char *_linear16_2_law = (signed char *)&linear16_2_law[32768];
	long index;
	int buf_size_in = 0;
	int buf_size_out = 0;
	int sample;
	unsigned int audio_sample_size_in = 2;
	unsigned int audio_sample_size_out = 2;

	if (lut_in != NULL) {
		return;
	}

	for (index = 0; index < 65535; index++) {
		_linear16_2_law[index - 32768] = bit_inverse(linear2alaw((short) index - 32768));
	}

	for (index = 0; index < 256; index++) {
		law_2_linear16[index] = alaw2linear(bit_inverse(index)) & 0xFFFF;
	}

	buf_size_in = audio_sample_size_in * 256;
	lut_in = (unsigned char*)malloc(buf_size_in);

	for (index = 0; index < buf_size_in; index += audio_sample_size_in) {
		sample = alaw2linear(bit_inverse((unsigned char)(index / 2)));
		lut_in[index + 0] = (unsigned char)(sample & 0xFF);
		lut_in[index + 1] = (unsigned char)(sample >> 8 & 0xFF);
	}

	buf_size_out = (1 + (audio_sample_size_out - 1) * 255) * 256;
	lut_out = (unsigned char*)malloc(buf_size_out);

	for (index = 0; index < buf_size_out; index++) {
		lut_out[index] = bit_inverse(linear2alaw((int)(signed char)(index >> 8) << 8 | (int)(index & 0xFF)));
	}

	lut_analyze = (unsigned char*)malloc(256);
	lut_a2s = (short int*)malloc(256 * sizeof(short));

	for (index = 0; index < 256; index++) {
		lut_analyze[index] = (unsigned char)((alaw2linear((unsigned char)bit_inverse(index)) / 256 & 0xFF) ^ 0x80);

		lut_a2s[index] = alaw2linear(bit_inverse(index));
	}
}

/**
 * \brief Initialize faxophone structure
 * \param handlers session handlers
 * \param host host name of router
 * \param controller listen controller or -1 for all
 * \return session pointer or NULL on error
 */
struct session *faxophone_init(struct session_handlers *handlers, const char *host, gint controller)
{
	int appl_id = -1;

	create_table_buffer();

	if (session == NULL) {
		if (host != NULL) {
#if HAVE_CAPI_36
			capi20ext_set_driver((char*)"fritzbox");
			capi20ext_set_host((char *) host);
			capi20ext_set_port(5031);
			capi20ext_set_tracelevel(0);
#else
			setHostName(host);
#endif
		}

		appl_id = capi_init(controller);
		if (appl_id <= 0) {
			g_debug("Initialization failed! Error %d!", appl_id);

			return NULL;
		} else {
			session = (struct session*)g_slice_alloc0(sizeof(struct session));

			g_mutex_init(&session->isdn_mutex);

			session->handlers = handlers;

			session->appl_id = appl_id;

			/* start capi transmission loop */
			faxophone_quit = 0;
			capi_thread = CREATE_THREAD("capi", capi_loop, NULL);
#ifndef WIN32
			setpriority(PRIO_PROCESS, 0, -10);
#endif
		}
	}

	return session;
}

/**
 * \brief Destroy faxophone
 * \param force force flag for capi_close()
 * \return error code 0
 */
int faxophone_close(int force)
{
	/* Close capi connection */
	//if (!force) {
	capi_close();
	//}

	if (session != NULL) {
		/* TODO: clear session! */
		faxophone_quit = 1;
		if (capi_thread != NULL) {
			g_thread_join(capi_thread);
		}
		faxophone_quit = 0;
		capi_thread = NULL;
	}

	session = NULL;

	return 0;
}

/**
 * \brief Get active faxophone session
 * \return session pointer or NULL on error
 */
struct session *faxophone_get_session(void)
{
	return session;
}
/**
 * \brief Faxophone connect
 * \param user_data faxophone plugin pointer
 * \return error code
 */
gboolean faxophone_connect(gpointer user_data)
{
	//struct profile *profile = profile_get_active();
  router_icl *rip=&ri;
	gboolean retry = TRUE;

again:
	session = faxophone_init(&session_handlers, rip->host/*router_get_host(profile)*/, 5/*g_settings_get_int(profile->settings, "phone-controller") + 1*/);
	if (!session && retry) {
		/* Maybe the port is closed, try to activate it and try again */
		router_dial_number(rip, PORT_ISDN1, "#96*3*");
		g_usleep(G_USEC_PER_SEC * 2);
		retry = FALSE;
		goto again;
	}

	return session != NULL;
}

/**
 * \brief Network disconnect callback
 * \param user_data faxophone plugin pointer
 * \return TRUE
 */
gboolean faxophone_disconnect(gpointer user_data)
{
	faxophone_close(TRUE);
	return TRUE;
}

typedef gboolean (*net_connect_func)(gpointer user_data);
typedef gboolean (*net_disconnect_func)(gpointer user_data);

struct net_event {
	net_connect_func connect;
	net_disconnect_func disconnect;
	gboolean is_connected;
	gpointer user_data;
};

/** Internal network event list */
static GSList *net_event_list = NULL;
/** Internal last known network state */
static gboolean net_online = FALSE;

/**
 * \brief Add network event
 * \param connect network connect function
 * \param disconnect network disconnect function
 * \param user_data user data pointer
 * \return net event id
 */
gconstpointer net_add_event(net_connect_func connect, net_disconnect_func disconnect, gpointer user_data)
{
	struct net_event *event;

	/* Sanity checks */
	g_assert(connect != NULL);
	g_assert(disconnect != NULL);

	/* Allocate new event */
	event = g_slice_new0(struct net_event);

	/* Set event functions */
	event->connect = connect;
	event->disconnect = disconnect;
	event->user_data = user_data;
	event->is_connected = FALSE;

	/* Add to network event list */
	net_event_list = g_slist_append(net_event_list, event);

	/* If current state is online, start connect() function */
	g_debug("%s(): net_online = %d", __FUNCTION__, net_online);
	if (net_online) {
		event->is_connected = event->connect(event->user_data);
		g_debug("%s(): is_connected = %d", __FUNCTION__, event->is_connected);
	}

	return event;
}

/**
 * \brief Remove network event by id
 * \param net_event_id network event id
 */
void net_remove_event(gconstpointer net_event_id)
{
	struct net_event *event = (struct net_event *) net_event_id;

	net_event_list = g_slist_remove(net_event_list, net_event_id);

	if (net_online) {
		event->is_connected = !event->disconnect(event->user_data);
	}

	g_slice_free(struct net_event, event);
}

/**
 * \brief Init faxophone support
 */
void faxophone_setup(void)
{
	net_event = net_add_event(faxophone_connect, faxophone_disconnect, NULL);
}

/**
 * \brief Shutdown router
 * \return TRUE
 */
void router_shutdown(void)
{
	/* Free router list */
	if (router_list != NULL) {
		g_slist_free(router_list);
		router_list = NULL;
	}

	/* Unset active router */
	active_router = NULL;
}


/**
 * \brief Shutdown routermanager
 * - Network monitor
 * - Profile
 * - Router
 * - Plugins
 * - Network
 * - Filter
 * - AppObject
 * - Log
 */
void routermanager_shutdown(void)
{
	/* Shutdown network monitor */
	//net_monitor_shutdown();

	/* Shutdown profiles */
	// profile_shutdown();

	/* Shutdown router */
	router_shutdown();

	/* Shutdown plugins */
	//plugins_shutdown();

	/* Shutdown network */
	net_shutdown();

	/* Shutdown filter */
	//filter_shutdown();

	/* Destroy app_object */
	g_clear_object(&app_object);

	/* Shutdown logging */
	//log_shutdown();
}

/**
 * \brief Hangup phone connection
 * \param connection active capi connection
 */
void phone_hangup(struct capi_connection *connection)
{
	if (connection == NULL) {
		return;
	}

	/* Hangup */
	capi_hangup(connection);
}

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

	fax_status = (struct fax_status*)connection->priv;
  printf("tiff_file: %s, src_no: %s, trg_no: %s, ident: %s, header: %s, remote_ident: %s, phase: %i, error_code: %i, sending: %i\n", fax_status->tiff_file,fax_status->src_no,fax_status->trg_no,fax_status->ident,fax_status->header,fax_status->remote_ident,fax_status->phase,fax_status->error_code,fax_status->sending);
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
}


/**
 * \brief Create new filter structure with given name
 * \param name filter name
 * \return filter structure pointer
 */
struct filter *filter_new(const gchar *name)
{
	struct filter *filter = g_slice_new0(struct filter);

	filter->name = g_strdup(name);
	filter->compare_or = FALSE;
	filter->rules = NULL;

	return filter;
}

/**
 * \brief Add new filter rule
 * \param filter filter structure
 * \param type type of filter
 * \param sub_type sub type of filter
 * \param entry ruleal entry
 */
void filter_rule_add(struct filter *filter, gint type, gint sub_type, gchar *entry)
{
	struct filter_rule *rule = g_slice_new(struct filter_rule);

	rule->type = type;
	rule->sub_type = sub_type;
	rule->entry = g_strdup(entry);

	filter->rules = g_slist_append(filter->rules, rule);
}

/** Internal filter list in memory */
static GSList *filter_list = NULL;

/**
 * \brief Sort filter by name
 * \param a pointer to first filter
 * \param b pointer to second filter
 * \return result of strcmp
 */
gint filter_sort_by_name(gconstpointer a, gconstpointer b)
{
	struct filter *filter_a = (struct filter *)a;
	struct filter *filter_b = (struct filter *)b;

	return strcmp(filter_a->name, filter_b->name);
}


/**
 * \brief Add filter structure to list
 * \param filter filter structure
 */
void filter_add(struct filter *filter)
{
	filter_list = g_slist_insert_sorted(filter_list, filter, filter_sort_by_name);
}


/**
 * \brief Load filter from storage - INTERNAL -
 */
static void filter_load(void)
{
	GFile *dir;
	GFileEnumerator *enumerator;
	GFileInfo *info;
	GError *error = NULL;
	gchar *path = g_build_filename(g_get_user_config_dir(), "routermanager/filters", G_DIR_SEPARATOR_S, NULL);

	dir = g_file_new_for_path(path);

	enumerator = g_file_enumerate_children(dir, G_FILE_ATTRIBUTE_STANDARD_NAME, G_FILE_QUERY_INFO_NONE, NULL, &error);
	if (!enumerator) {
		return;
	}

	while ((info = g_file_enumerator_next_file(enumerator, NULL, NULL))) {
		const gchar *name = g_file_info_get_name(info);
		gchar *tmp = g_strconcat(path, name, NULL);
		GKeyFile *keyfile = g_key_file_new();
		struct filter *filter;
		gsize cnt;
		gchar **groups;
		gint idx;

		g_key_file_load_from_file(keyfile, tmp, G_KEY_FILE_NONE, NULL);
		groups = g_key_file_get_groups(keyfile, &cnt);
		filter = filter_new(name);
		for (idx = 0; idx < cnt; idx++) {
			gint type;
			gint subtype;
			gchar *entry;

			type = g_key_file_get_integer(keyfile, groups[idx], "type", NULL);
			subtype = g_key_file_get_integer(keyfile, groups[idx], "subtype", NULL);
			entry =  g_key_file_get_string(keyfile, groups[idx], "entry", NULL);
			filter_rule_add(filter, type, subtype, entry);

			filter->file = g_strdup(tmp);
			g_free(entry);
		}
		filter_add(filter);

		g_key_file_unref(keyfile);

		g_free(tmp);
	}

	g_object_unref(enumerator);
}

void filter_init(void)
{
	struct filter *filter;

	filter_load();

	if (filter_list) {
		return;
	}

	/* No self-made filters available, create standard filters */

	/* All calls */
	filter = filter_new(_("All calls"));
	filter_rule_add(filter, 0, CALL_TYPE_ALL, NULL);
	filter_add(filter);

	/* Incoming calls */
	filter = filter_new(_("Incoming calls"));
	filter_rule_add(filter, 0, CALL_TYPE_INCOMING, NULL);
	filter_add(filter);

	/* Missed calls */
	filter = filter_new(_("Missed calls"));
	filter_rule_add(filter, 0, CALL_TYPE_MISSED, NULL);
	filter_add(filter);

	/* Outgoing calls */
	filter = filter_new(_("Outgoing calls"));
	filter_rule_add(filter, 0, CALL_TYPE_OUTGOING, NULL);
	filter_add(filter);

	/* Fax */
	filter = filter_new(_("Fax"));
	filter_rule_add(filter, 0, CALL_TYPE_FAX, NULL);
	filter_add(filter);

	/* Answering machine */
	filter = filter_new(_("Answering machine"));
	filter_rule_add(filter, 0, CALL_TYPE_VOICE, NULL);
	filter_add(filter);

	/* Fax Report */
	filter = filter_new(_("Fax Report"));
	filter_rule_add(filter, 0, CALL_TYPE_FAX_REPORT, NULL);
	filter_add(filter);

	/* Voice Record */
	filter = filter_new(_("Record"));
	filter_rule_add(filter, 0, CALL_TYPE_RECORD, NULL);
	filter_add(filter);

	/* Blocked calls */
	filter = filter_new(_("Blocked"));
	filter_rule_add(filter, 0, CALL_TYPE_BLOCKED, NULL);
	filter_add(filter);

}

/**
 * \brief Emit signal: process-fax
 * \param filename fax filename in spooler directory
 */
void emit_fax_process(const gchar *filename)
{
	g_signal_emit(app_object, app_object_signals[ACB_FAX_PROCESS], 0, filename);
}

#define BUFFER_LENGTH 1024

gpointer print_server_thread(gpointer data)
{
	GSocket *server = (GSocket*)data;
	GSocket *sock;
	GError *error = NULL;
	gsize len;
	gchar *file_name;
	char buffer[BUFFER_LENGTH];
	ssize_t write_result;
	ssize_t written;

	while (TRUE) {
		sock = g_socket_accept(server, NULL, &error);
		g_assert_no_error(error);

		file_name = g_strdup_printf("%s/fax-XXXXXX", g_get_tmp_dir());
		int file_id = g_mkstemp(file_name);

		if (file_id == -1) {
			g_warning("Can't open temporary file");
			continue;
		}

		g_debug("file: %s (%d)", file_name, file_id);

		do {
			len = g_socket_receive(sock, buffer, BUFFER_LENGTH, NULL, &error);

			if (len > 0) {
				written = 0;
				do {
					write_result = write(file_id, buffer + written, len);
					if (write_result > 0) {
						written += write_result;
					}
				} while (len != written && (write_result != -1 || errno == EINTR));
			}
		} while (len > 0);

		if (len == 0) {
			g_debug("Print job received on socket");

			emit_fax_process(file_name);
		}

		g_socket_close(sock, &error);
		g_assert_no_error(error);
	}

	return NULL;
}

/**
 * \brief Print error quark
 * \return quark
 */
GQuark rm_print_error_quark(void)
{
	return g_quark_from_static_string("rm-print-error-quark");
}

gboolean fax_printer_init(GError **error)
{
	GSocket *socket = NULL;
	GInetAddress *inet_address = NULL;
	GSocketAddress *sock_address = NULL;
	GError *fax_error = NULL;

	socket = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, &fax_error);
	if (socket == NULL) {
		g_debug("Could not create socket. Error: '%s'", fax_error->message);
		g_set_error(error, RM_ERROR, RM_ERROR_FAX, "Could not create socket. Error: '%s'", fax_error ? fax_error->message : "");
		g_error_free(fax_error);
		return FALSE;
	}

	inet_address = g_inet_address_new_from_string("127.0.0.1");

	sock_address = g_inet_socket_address_new(inet_address, 9100);
	if (sock_address == NULL) {
		g_debug("Could not create sock address on port 9100");
		g_object_unref(socket);
		g_set_error(error, RM_ERROR, RM_ERROR_FAX, "%s", "Could not create sock address on port 9100");
		return FALSE;
	}

	if (g_socket_bind(socket, sock_address, TRUE, &fax_error) == FALSE) {
		g_debug("Could not bind to socket. Error: %s", fax_error->message);
		g_set_error(error, RM_ERROR, RM_ERROR_FAX, "Could not bind to socket. Error: %s", fax_error->message);
		g_error_free(fax_error);
		g_object_unref(socket);
		return FALSE;
	}

	if (g_socket_listen(socket, &fax_error) == FALSE) {
		g_debug("Could not listen on socket. Error: %s", fax_error->message);
		g_set_error(error, RM_ERROR, RM_ERROR_FAX, "Could not listen on socket. Error: %s", fax_error->message);
		g_error_free(fax_error);
		g_object_unref(socket);
		return FALSE;
	}

	g_debug("Fax Server running on port 9100");

	g_thread_new("printserver", print_server_thread, socket);

	return TRUE;
}

/**
 * \brief Get directory of requested type
 * \param type directory type name
 * \return directory as duplicated string
 */
gchar *get_directory(gchar *type)
{
#ifdef G_OS_WIN32
	GFile *directory;
	GFile *child;
	gchar *tmp;

	tmp = g_win32_get_package_installation_directory_of_module(NULL);

	directory = g_file_new_for_path(tmp);
	g_free(tmp);

	child = g_file_get_child(directory, type);
	g_object_unref(directory);

	directory = child;

	tmp = g_file_get_path(directory);
	g_object_unref(directory);

	return tmp;
#elif __APPLE__
	gchar *bundle = gtkosx_application_get_bundle_path();

	if (gtkosx_application_get_bundle_id()) {
		return g_strdup_printf("%s/Contents/Resources/%s", bundle, type);
	} else {
		return g_strdup_printf("%s/../%s", bundle, type);
	}
#else
	return g_strdup(type);
#endif
}

static gchar *plugin_dir = NULL;
#define ROUTERMANAGER_PLUGINS (gchar*)"/usr/lib64/routermanager"
/**
 * \brief Initialize directory paths
 */
void init_directory_paths(void)
{
	plugin_dir = get_directory(ROUTERMANAGER_PLUGINS);
}

/**
 * \brief Return plugin directory
 * \return plugin directory string
 */
static gchar *get_plugin_dir(void)
{
	return plugin_dir;
}

/** Internal search path list */
static GSList *search_path_list = NULL;
/** Internal peas extension set */
static PeasExtensionSet *exten = NULL;
/** peas engine */
PeasEngine *engine = NULL;

/**
 * \brief Add additional search path for peas
 * \param path path to search for plugins for
 */
void routermanager_plugins_add_search_path(gchar *path)
{
	search_path_list = g_slist_append(search_path_list, g_strdup(path));
}

/**
 * \brief Add extension callback
 * \param set peas extension set
 * \param info peas plugin info
 * \param exten peas extension
 * \param unused unused data poiner
 */
static void plugins_extension_added_cb(PeasExtensionSet *set, PeasPluginInfo *info, PeasExtension *exten, gpointer unused)
{
	/* Active plugin now */
	g_debug(" + %s (%s) activated", peas_plugin_info_get_name(info), peas_plugin_info_get_module_name(info));
	peas_activatable_activate(PEAS_ACTIVATABLE(exten));
}

/**
 * \brief Remove extension callback
 * \param set peas extension set
 * \param info peas plugin info
 * \param exten peas extension
 * \param unused unused data poiner
 */
static void plugins_extension_removed_cb(PeasExtensionSet *set, PeasPluginInfo *info, PeasExtension *exten, gpointer unused)
{
	/* Remove plugin now */
	if (!peas_plugin_info_is_builtin(info)) {
		g_debug(" - %s (%s) deactivated", peas_plugin_info_get_name(info), peas_plugin_info_get_module_name(info));
	}
	peas_activatable_deactivate(PEAS_ACTIVATABLE(exten));
}

/**
 * \brief Find and load builtin plugins
 */
void plugins_init(void)
{
	GSList *slist;
	const GList *list;

	/* Get default engine */
	engine = peas_engine_get_default();

	/* Set app object as object to engine */
	exten = peas_extension_set_new(engine, PEAS_TYPE_ACTIVATABLE, "object", app_object, NULL);

	/* Connect extension added/removed signals */
	g_signal_connect(exten, "extension-added", G_CALLBACK(plugins_extension_added_cb), NULL);
	g_signal_connect(exten, "extension-removed", G_CALLBACK(plugins_extension_removed_cb), NULL);

	/* Look for plugins in plugin_dir */
	peas_engine_add_search_path(engine, ROUTERMANAGER_PLUGINS, ROUTERMANAGER_PLUGINS);

	/* And all other directories */
	for (slist = search_path_list; slist != NULL; slist = slist->next) {
		gchar *plugin_dir = (gchar*)slist->data;
    printf("1 Plugin, data: %s\n",slist->data);

		peas_engine_add_search_path(engine, plugin_dir, plugin_dir);
	}

	/* In addition to C we want to support python plugins */
	peas_engine_enable_loader(engine, "python3");

	/* Traverse through detected plugins and loaded builtin plugins now */
	for (list = peas_engine_get_plugin_list(engine); list != NULL; list = list->next) {
		PeasPluginInfo *info = (PeasPluginInfo*)list->data;
    printf("2 Plugin, data: %s %i ",(const char*)list->data, strlen((const char*)list->data));

		if (peas_plugin_info_is_builtin(info)) {
      printf(" builtin\n");
			peas_engine_load_plugin(engine, info);
		}
    printf("\n");
	}
}

/**
 * \brief Initialize router (if available set internal router structure)
 * \return TRUE on success, otherwise FALSE
 */
gboolean router_init(void)
{
	if (g_slist_length(router_list)) {
		return TRUE;
	}

	g_warning("No router plugin registered!");
	return FALSE;
}

/**
 * \brief Return network status text
 * \param state network state
 * \return network state in text
 */
static inline gchar *net_state(gboolean state)
{
	return state ? (gchar*)"online" : (gchar*)"offline";
}

/**
 * \brief Handle network state changes
 * \param state current network state
 */
void net_monitor_state_changed(gboolean state)
{
	GSList *list;

	/* Compare internal and new network state, only handle new states */
	if ((net_online == state) && (!state || 1/*profile_get_active()*/)) {
		g_debug("Network state repeated, ignored (%s)", net_state(state));
		return;
	}

	g_debug("Network state changed from %s to %s", net_state(net_online), net_state(state));

	/* Set internal network state */
	net_online = state;

	/* Call network function depending on network state */
	if (!net_online) {
		/* Offline: disconnect all network events */
		for (list = net_event_list; list != NULL; list = list->next) {
			struct net_event *event = (struct net_event*)list->data;

			g_debug("%s(): 1. is_connected = %d", __FUNCTION__, event->is_connected);
			if (event->is_connected) {
				event->is_connected = !event->disconnect(event->user_data);
			}
			g_debug("%s(): 2. is_connected = %d", __FUNCTION__, event->is_connected);
		}

		/* Disable active profile */
		// profile_set_active(NULL);
	} else {
		/* Online: Try to detect active profile */
		if (1/*profile_detect_active()*/) {
			/* We have an active profile: Connect to all network events */
			for (list = net_event_list; list != NULL; list = list->next) {
				struct net_event *event = (struct net_event*)list->data;

				g_debug("%s(): 1. is_connected = %d", __FUNCTION__, event->is_connected);
				if (!event->is_connected) {
					g_debug("%s(): Calling connect", __FUNCTION__);
					event->is_connected = event->connect(event->user_data);
				}
				g_debug("%s(): 2. is_connected = %d", __FUNCTION__, event->is_connected);
			}
		}
	}
}

/**
 * \brief Network monitor changed callback
 * \param monitor GNetworkMonitor pointer
 * \param available network available flag
 * \param unused unused user data pointer
 */
void net_monitor_changed_cb(GNetworkMonitor *monitor, gboolean available, gpointer unused)
{
	net_monitor_state_changed(available);
}

/**
 * \brief Check if router is present
 * \param router_info router information structure
 * \return present state
 */
gboolean router_present(struct router_icl *ri)
{
  GSList *list;
  g_debug("%s(): called", __FUNCTION__);
  if (!router_list) {
    g_debug("router_present: keine router_list");
    return FALSE;
  }
  unsigned long ru=0;
  for (list = router_list; list != NULL; list = list->next) {
    struct hrouter *router = (struct hrouter*)list->data;
      g_debug("%lu: %s",++ru,router->name);
    if (router->present((struct router_icl*)ri)) { // !strcmp(router->name,"FRITZ!Box")) {
      active_router = router;
      g_debug("router_present: %s",router->name);
      return TRUE;
    }
      g_debug("not router_present: %s",router->name);
  }

  g_debug("router_present: keiner praesent");
  return FALSE;
}


static GList *routers = NULL;

static void device_proxy_available_cb(GUPnPControlPoint *cp, GUPnPDeviceProxy *proxy)
{
	struct router_icl *ri = g_slice_new0(struct router_icl);
	GUPnPDeviceInfo *info = GUPNP_DEVICE_INFO(proxy);
	const SoupURI *uri;

	uri = gupnp_device_info_get_url_base(info);
	ri->host = g_strdup(soup_uri_get_host((SoupURI*)uri));

	/* Scan for router and add detected devices */
	if (router_present(ri) == TRUE) {
    printf("device_proxy_available_cb 2\n");
    routers = g_list_append(routers, ri);
	}
}

static void device_proxy_unavailable_cb(GUPnPControlPoint *cp, GUPnPDeviceProxy *proxy)
{
	g_debug("%s(): %s", __FUNCTION__, gupnp_device_info_get_model_name(GUPNP_DEVICE_INFO(proxy)));
}

GList *ssdp_get_routers(void)
{
	if (!routers) {
		struct router_icl *ri = g_slice_new0(struct router_icl);

		/* Fallback - In case no routers have been detected, try at least fritz.box manually */
		ri->host = g_strdup("fritz.box");

		/* Scan for router and add detected devices */
		if (router_present(ri) == TRUE) {
			routers = g_list_append(routers, ri);
		}
	}

	return routers;
}

static GUPnPContextManager *context_manager;
static void on_context_available(GUPnPContextManager *manager, GUPnPContext *context, gpointer user_data)
{
	GUPnPControlPoint *cp;

	cp = gupnp_control_point_new(context, "urn:schemas-upnp-org:device:InternetGatewayDevice:1");

	g_signal_connect(cp, "device-proxy-available", G_CALLBACK(device_proxy_available_cb), NULL);
	g_signal_connect(cp, "device-proxy-unavailable", G_CALLBACK (device_proxy_unavailable_cb), NULL);

	gssdp_resource_browser_set_active(GSSDP_RESOURCE_BROWSER(cp), TRUE);

	gupnp_context_manager_manage_control_point(context_manager, cp);

	g_object_unref (cp);
}

void ssdp_init(void)
{
	context_manager = gupnp_context_manager_new(NULL, 1900);
	g_signal_connect(context_manager, "context-available", G_CALLBACK(on_context_available), NULL);
}

/**
 * \brief Initialize network monitor
 * \return TRUE on success, otherwise FALSE
 */
gboolean net_monitor_init(void)
{
#ifdef G_OS_UNIX
	GNetworkMonitor *monitor = g_network_monitor_get_default();
  printf("net_monitor_init 1\n");

	g_return_val_if_fail(monitor != NULL, FALSE);
  printf("net_monitor_init 2\n");


	/* Connect signal handler */
	g_signal_connect(monitor, "network-changed", G_CALLBACK(net_monitor_changed_cb), NULL);
  printf("net_monitor_init 3\n");

	ssdp_init();

#if GLIB_CHECK_VERSION(2,44,0)
  printf("net_monitor_init 5\n");
	net_monitor_state_changed(g_network_monitor_get_connectivity(monitor) != G_NETWORK_CONNECTIVITY_LOCAL);
#else
  printf("net_monitor_init 6\n");
	net_monitor_state_changed(g_network_monitor_get_network_available(monitor));
#endif
#else
  printf("net_monitor_init 6\n");
	net_monitor_state_changed(TRUE);
#endif

	return TRUE;
}

/**
 * \brief Shutdown network monitor (disconnect signal and shutdown event callbacks)
 */
void net_monitor_shutdown(void)
{
#ifdef G_OS_UNIX
	GNetworkMonitor *monitor = g_network_monitor_get_default();

	/* Disconnect signal handler */
	g_signal_handlers_disconnect_by_func(monitor, (gpointer)G_CALLBACK(net_monitor_changed_cb), NULL);
#endif
}

/**
 * \brief Initialize routermanager
 * \return TRUE on success, FALSE on error
 */
gboolean routermanager_init(router_icl *ri,GError **error)
{
	/* Init filter */
  printf("routermanager_init 1\n");
	filter_init();
  printf("routermanager_init 2\n");

	/* Init fax printer */
	if (!fax_printer_init(error)) {
		return FALSE;
	}
  printf("routermanager_init 3\n");

	/* Initialize network */
	net_init(ri);
  printf("routermanager_init 4\n");

	/* Load plugins depending on ui (router, audio, address book, reverse lookup...) */
	routermanager_plugins_add_search_path(get_plugin_dir());
  printf("routermanager_init 5\n");

	/* Initialize plugins */
//	plugins_init();
  printf("routermanager_init 6\n");

	/* Check password manager */
  /*
	if (!password_manager_get_plugins()) {
		g_set_error(error, RM_ERROR, RM_ERROR_ROUTER, "%s", "No password manager plugins active");
		return FALSE;
	}
  printf("routermanager_init 7\n");
  */

	/* Initialize router */
	if (!router_init()) {
		g_set_error(error, RM_ERROR, RM_ERROR_ROUTER, "%s", "Failed to initialize router");
		return FALSE;
	}
  printf("routermanager_init 8\n");

	/* Initialize profiles */
	// profile_init();
  printf("routermanager_init 9\n");

	/* Initialize network monitor */
	net_monitor_init();
  printf("routermanager_init 10\n");

	return TRUE;
}


/**
 * \brief Initialize action structure - load actions selected by profile and connect to connection-notify signal
 * \param profile profile pointer
 */
/*
void action_init(struct profile *profile)
{
	gchar **actions;
	guint count;
	guint index;

	// Based upon the profile settings load the action list
	actions = g_settings_get_strv(profile->settings, "actions");

	// Load all available actions
	count = g_strv_length(actions);
	for (index = 0; index < count; index++) {
		action_load(profile, actions[index]);
	}

	g_strfreev(actions);

	// Connect to connection-notify signal
	g_signal_connect(G_OBJECT(app_object), "connection-notify", G_CALLBACK(action_connection_notify_cb), profile);
}
*/

/**
 * \brief Initialize audio subsystem
 * \param profile profile structure
 */
/*
void audio_init(struct profile *profile)
{
	gchar *name = g_settings_get_string(profile->settings, "audio-plugin");

	audio_set_default(name);

	// In case no internal audio is set yet, set it to the first one
	if (!internal_audio && audio_list) {
		internal_audio = audio_list->data;
	}
}
*/

/**
 * \brief Add plugins information to profile settings
 */
/*
void plugins_user_plugins(void)
{
	g_settings_bind(profile_get_active()->settings, "active-plugins", engine, "loaded-plugins", G_SETTINGS_BIND_DEFAULT);
}
*/

int main(int argc, char **argv)
{
  ri.ftpusr=(gchar*)"ftpuser";
  ri.ftppwd=(gchar*)"friex123";
  ri.user=(gchar*)"";
  ri.password=(gchar*)"bach17raga";
  ri.faxreportdir=(gchar*)"/root/rogerj";
  net_init(&ri);
  net_shutdown();
  ri.host=(gchar*)"fritz.box";
  fritzbox_present(&ri);
//  plugins_user_plugins();
//  audio_init(&ri);
//  action_init(&ri);
  faxophone_setup();
  if (ri.name) {
    if (fritzbox_login(&ri)) {
      printf("-> !!!!!!!! vor fritzbox_get_settings !!!!!!!!!!!!!\n");
//      fritzbox_get_settings(&ri);
      printf("- !!!!!!!! vor fritzbox_load_journal !!!!!!!!!!!!!\n");
#ifdef ab
      fritzfon_get_books(&ri);
      // GSList *contacts=address_book_get_contacts();
      fritzfon_read_book();
      for(GSList *list=fritzfon_books;list;list=list->next) {
       struct fritzfon_book *book=(struct fritzfon_book*)list->data;
       printf("Buch: %s, Name: %s\n",book->id, book->name);
      }
#endif
      // address_book_contact_process_cb
////      g_signal_connect(G_OBJECT(app_object),"journal-loaded", G_CALLBACK(journal_loaded_cb),NULL);
//      gchar* tojournal=0;
//      fritzbox_load_journal(&ri,&tojournal);
      gchar *tiff = NULL;
      gchar *file_name=(gchar*)"/DATA/down/hallo.pdf";
      printf("vor routermanager_init\n");
      routermanager_init(&ri,NULL);
      printf("nach routermanager_init\n");
      g_signal_connect(app_object, "connection-status", G_CALLBACK(fax_connection_status_cb), NULL);
      printf("nach connection-status\n");
      g_signal_connect(app_object, "connection-established", G_CALLBACK(capi_connection_established_cb), NULL);
      printf("nach connection-established\n");
      g_signal_connect(app_object, "connection-terminated", G_CALLBACK(capi_connection_terminated_cb), NULL);
      printf("nach connection-terminated\n");
      tiff = convert_fax_to_tiff(file_name);
      if (tiff) {
        gchar *number = (gchar*)"6150166";
        gboolean suppress=false;
        printf("vor faxophone_connect\n");
        faxophone_connect(&ri);
        printf("nach faxophone_connect\n");
        gpointer connection = fax_dial(&ri,tiff, number, false);
        printf("nach fax_dial\n");
        //faxophone_disconnect();
        if (!connection) {
          g_error("could not create connection!");
          exit(-2);
        }
        printf("vor g_main_loop_new\n");
        main_loop = g_main_loop_new(NULL, FALSE);
        printf("vor Mail-Loop\n");
        g_main_loop_run(main_loop);
        printf("nach Mail-Loop\n");
        routermanager_shutdown();
        // g_unlink(tiff);

      } else {
        g_warning("Error converting print file to TIFF!");
        exit(-4);
      }
    }
  }

  printf("Fertig!\n");
}
