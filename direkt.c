#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libsoup/soup.h>
#include <string>
#include <iostream>
#include <vector>
#include <capiutils.h>
#include "/home/schade/rogerj/wand/libroutermanager/libfaxophone/fax.h"
#include "/home/schade/rogerj/wand/libroutermanager/libfaxophone/phone.h"
#include "/home/schade/rogerj/wand/libroutermanager/libfaxophone/faxophone.h"
#include "/home/schade/rogerj/wand/libroutermanager/fax_phone.h"
#include "/home/schade/rogerj/wand/libroutermanager/audio.h"
#include "/home/schade/rogerj/wand/libroutermanager/appobject.h"
#include "/home/schade/rogerj/wand/libroutermanager/appobject-emit.h"
#include "/home/schade/rogerj/wand/libroutermanager/logging.h"
#include "/home/schade/rogerj/wand/libroutermanager/net_monitor.h"
#include "/home/schade/rogerj/wand/libroutermanager/routermanager.h"
/*
#include "/home/schade/rogerj/wand/libroutermanager/router.h"
#include "/home/schade/rogerj/wand/libroutermanager/routermanager.h"
*/

std::string nix="";

std::string xmlex(std::string data,std::string lim,std::string lim2=nix,size_t *p2p=0)
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

/**
 * \brief Make dots (UTF8 -> UTF16)
 * \param str UTF8 string
 * \return UTF16 string
 */
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

class fbcl
{
  private:
    int result;
    std::string usr;
    std::string pwd;
    std::string sid,si0;
    const char* data;
    size_t read;
    GTimer *stim;
    std::string url;
    std::string host;
    SoupMessage *msg;
    SoupSession *soup_session;
    std::vector<std::string> numn;
  public:
    int eingel;
  private:
    int fb_check_login_blocked();

  public:
    fbcl();
    void fb_login_05_50();
    int loadj();
    int fb_get_settings_05_50();
    void fb_detect_controller_05_50();
};

fbcl::fbcl()
{
  sid=si0="0000000000000000";
  usr="libelle17";
  pwd="bach17raga";
  host="192.168.178.1";
  stim=0;
  eingel=0;
}

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


/**
 * \brief Get settings via lua-scripts (phone numbers/names, default controller, tam setting, fax volume/settings, prefixes, default dial port)
 * \param profile profile information structure
 * \return error code
 */
int fbcl::fb_get_settings_05_50(/*struct profile *profile*/)
{
	gint index;
	/* Login */
  if (!eingel) return 0;
  soup_session=soup_session_new_with_options(SOUP_SESSION_TIMEOUT,5,NULL);

	/* Extract phone numbers */
  url="http://"+host+"/fon_num/fon_num_list.lua";
	msg = soup_form_request_new(SOUP_METHOD_GET, url.c_str(), "sid", sid.c_str(), NULL);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
    printf("%s(): Received Status code: %d\n",__FUNCTION__ ,msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

  if (data) {
    numn.clear();
    size_t p2=0;
    while (1) {
      std::string num=xmlex(data,"td title=\"\"","td",&p2);
      int schonda=0;
      for(size_t i=0;i<numn.size();i++) {
        if (num==numn[i]) {
          schonda=1;
          break;
        }
      }
      if (!schonda) numn.push_back(num);
      if (num.empty()) break;
    }
  }
	g_object_unref(msg);

  url="http://"+host+"/fon_devices/fondevices_list.lua";
	msg = soup_form_request_new(SOUP_METHOD_GET, url.c_str(), "sid", sid.c_str(), NULL);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
    printf("%s(): Received Status code: %d\n",__FUNCTION__ ,msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

  if (data) {
    //std::cout<<data<<std::endl;
    fb_detect_controller_05_50();
  }
	g_object_unref(msg);
  /*
	// Extract phone names, default controller
	url = g_strdup_printf("http://%s/fon_devices/fondevices_list.lua", router_get_host(profile));
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", profile->router_info->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
    printf("%s(): Received Status code: %d\n",__FUNCTION__ ,msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	log_save_data("fritzbox-05_50-get-settings-1.html", data, read);
	g_assert(data != NULL);

	// Try to detect controller
	fritzbox_detect_controller_05_50(profile, data);

	// Extract phone names
	for (index = 0; index < PORT_MAX; index++) {
		gchar *value;

		value = xml_extract_list_value(data, fritzbox_phone_ports[index].name);
		if (value) {
			if (!EMPTY_STRING(value)) {
				g_debug("Port %d: '%s'", index, value);
			}
			g_settings_set_string(profile->settings, router_phone_ports[index].name, value);
			g_free(value);
		}
	}

	// FRITZ!OS 5.50 has broken the layout of DECT, therefore we must scan again for DECT
	fritzbox_extract_dect_05_50(profile, data);

	// Check if TAM is using USB-Stick
	gchar *stick = xml_extract_input_value(data, "tam:settings/UseStick");
	if (stick && atoi(&stick[0])) {
		g_settings_set_int(profile->settings, "tam-stick", atoi(stick));
	} else {
		g_settings_set_int(profile->settings, "tam-stick", 0);
	}
	g_free(stick);

	g_object_unref(msg);

	// Extract city/country/area prefix
	url = g_strdup_printf("http://%s/fon_num/sip_option.lua", router_get_host(profile));
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", profile->router_info->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
    printf("%s(): Received Status code: %d\n",__FUNCTION__ ,msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	log_save_data("fritzbox-05_50-get-settings-2.html", data, read);
	g_assert(data != NULL);

	gchar *value;

	value = xml_extract_list_value(data, "telcfg:settings/Location/LKZ");
	if (value != NULL && strlen(value) > 0) {
		g_debug("lkz: '%s'", value);
	}
	g_settings_set_string(profile->settings, "country-code", value);
	g_free(value);

	value = xml_extract_list_value(data, "telcfg:settings/Location/LKZPrefix");
	if (value != NULL && strlen(value) > 0) {
		g_debug("lkz prefix: '%s'", value);
	}
	g_settings_set_string(profile->settings, "international-call-prefix", value);
	g_free(value);

	value = xml_extract_list_value(data, "telcfg:settings/Location/OKZ");
	if (value != NULL && strlen(value) > 0) {
		g_debug("okz: '%s'", value);
	}
	g_settings_set_string(profile->settings, "area-code", value);
	g_free(value);

	value = xml_extract_list_value(data, "telcfg:settings/Location/OKZPrefix");
	if (value != NULL && strlen(value) > 0) {
		g_debug("okz prefix: '%s'", value);
	}
	g_settings_set_string(profile->settings, "national-call-prefix", value);
	g_free(value);

	g_object_unref(msg);

	// Extract Fax information
	if (FIRMWARE_IS(6, 0)) {
		fritzbox_get_fax_information_06_00(profile);
	} else {
		fritzbox_get_fax_information_05_50(profile);
	}

	// Extract default dial port 
	url = g_strdup_printf("http://%s/fon_num/dial_foncalls.lua", router_get_host(profile));
	msg = soup_form_request_new(SOUP_METHOD_GET, url,
	                            "sid", profile->router_info->session_id,
	                            NULL);
	g_free(url);

	soup_session_send_message(soup_session, msg);
	if (msg->status_code != 200) {
    printf("%s(): Received Status code: %d\n",__FUNCTION__ ,msg->status_code);
		g_object_unref(msg);
		return FALSE;
	}
	data = msg->response_body->data;
	read = msg->response_body->length;

	log_save_data("fritzbox-05_50-get-settings-3.html", data, read);
	g_assert(data != NULL);

	gchar *dialport = xml_extract_list_value(data, "telcfg:settings/DialPort");
	if (dialport) {
		gint port = atoi(dialport);
		gint phone_port = fritzbox_find_phone_port(port);
		g_debug("Dial port: %s, phone_port: %d", dialport, phone_port);
		router_set_phone_port(profile, phone_port);
	}
	g_free(dialport);

	g_object_unref(msg);

	// The end - exit
	fritzbox_logout(profile, FALSE);

  */
	g_object_unref(soup_session);
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

#define EMPTY_STRING(x) (!(x) || !strlen(x))
/**
 * \brief Number compare function
 * \param a string a
 * \param b string b
 * \return return value of strcmp
 */
gint number_compare(gconstpointer a, gconstpointer b)
{
	return strcmp((const char*)a, (const char*)b);
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
        std::cout<<"fon: "<<fon<<std::endl;
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
void fbcl::fb_detect_controller_05_50()
{
	gint index;
	gint type = -1;
	gint port;
	GSList *number_list = NULL;

	// POTS first!
	if (extract_number_05_50(&number_list, data, (gchar*)"telcfg:settings/MSN/POTS")) {
		type = 3;
		goto set;
	}

	// PortX-MSN
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

	// NTHotDialList
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

	// SIP
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

  /*
	g_debug("Setting controllers to %d", type);
	g_settings_set_int(profile->settings, "fax-controller", type);
	g_settings_set_int(profile->settings, "phone-controller", type);
  */
set:
  std::cout<<"type: "<<type<<std::endl;
  return;
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
gint spandsp_init_hier(const gchar *tiff_file, gboolean sending, gchar modem, gchar ecm, const gchar *lsi, const gchar *local_header_info, struct capi_connection *connection)
{
	t30_state_t *t30;
	logging_state_t *log_state;
	gint supported_resolutions = 0;
	gint supported_image_sizes = 0;
	gint supported_modems = 0;
	struct fax_status *status = (fax_status*)connection->priv;

	status->fax_state = fax_init(NULL, sending);
	g_debug("status->fax_state: %p", status->fax_state);

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
	if (log_level >= 1) {
		log_state = t30_get_logging_state(t30);
		span_log_set_level(log_state, 0xFFFFFF);

		if (!logging) {
			logging = spandsp_msg_log;
		}

		span_log_set_message_handler(log_state, logging);
	}

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
	/*
	t30_set_phase_b_handler(t30, phase_handler_b, (void *) connection);
	t30_set_phase_d_handler(t30, phase_handler_d, (void *) connection);
	t30_set_phase_e_handler(t30, phase_handler_e, (void *) connection);

	t30_set_real_time_frame_handler(t30, real_time_frame_handler, (void *) connection);
*/
	return 0;
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

gboolean faxophone_connect(gpointer user_data);
gboolean faxophone_disconnect(gpointer user_data);

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
	printf("!!!!!!!!Anfang connection_status\n");
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

/**
 * \brief Faxophone connect
 * \param user_data faxophone plugin pointer
 * \return error code
 */
gboolean faxophone_connect_hier(gpointer user_data)
{
//	struct profile *profile = profile_get_active();
	gboolean retry = TRUE;
	gchar* host=(gchar*)"fritz.box"; // router_get_host(profile);
	gint phonecontr=4; // g_settings_get_int(profile->settings, "phone-controller");
	printf("Beginn faxophone_connect_hier, host: %s, phone-controller: %i\n",host,phonecontr);
again:
	session = faxophone_init(&session_handlers, host, phonecontr + 1);
/*
	if (!session && retry) {
		// Maybe the port is closed, try to activate it and try again 
		router_dial_number(profile, PORT_ISDN1, "#96*3*");
		g_usleep(G_USEC_PER_SEC * 2);
		retry = FALSE;
		goto again;
	}
*/
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
	net_event = net_add_event(faxophone_connect_hier, faxophone_disconnect, NULL);

	/* Only show messages >= INFO */
	log_set_level(G_LOG_LEVEL_INFO);

//  fb.loadj();
//  fb.fb_get_settings_05_50();
		g_signal_connect(app_object, "connection-status", G_CALLBACK(fax_connection_status_cb), NULL);
		g_signal_connect(app_object, "connection-established", G_CALLBACK(capi_connection_established_cb), NULL);
		g_signal_connect(app_object, "connection-terminated", G_CALLBACK(capi_connection_terminated_cb), NULL);

	system("gs -q -dNOPAUSE -dSAFER -dBATCH -sDEVICE=tiffg32d -sPAPERSIZE=a4 -dFIXEDMEDIA -r204x98 -sOutputFile=t0.pdf.tif ~/rogerj/wand/t0.pdf");
	gpointer user_data;
printf("4 !!!!!!!!!!!!!!!!!!!\n");
	faxophone_connect_hier(user_data);
printf("5 !!!!!!!!!!!!!!!!!!!\n");
//	exit(0);
	// aus fax_dial
	struct capi_connection * conn=fax_send_hier((gchar*)"t0.pdf.tif",2,1,5,4,(gchar*)"6150166",(gchar*)"619712",(gchar*)"+496150166",(gchar*)"G.Schade",0);
	/* Create and start g_main_loop */

	printf("Vor main_loop\n");
  // fax_transfer
	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);
	printf("Nach main_loop\n");

	/* Shutdown routermanager */
	//routermanager_shutdown();
	/* Destroy app_object */
	g_clear_object(&app_object);

	/* Shutdown logging */
	log_shutdown();

	faxophone_disconnect(user_data);
}
