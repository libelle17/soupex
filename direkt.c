#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libsoup/soup.h>
#include <string>
#include <iostream>
#include <vector>
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


int main(int argc, char** argv)
{
  fbcl fb;
  fb.fb_login_05_50();
  std::cout<<"eingel: "<<fb.eingel<<std::endl;
//  fb.loadj();
  fb.fb_get_settings_05_50();
}
