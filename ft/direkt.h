#include <string>
#include <vector>
#define EMPTY_STRING(x) (!(x) || !strlen(x))
extern const std::string nix;
std::string xmlex(std::string data,std::string lim,std::string lim2=nix,size_t *p2p=0);
// Active router structure 
//extern struct router *active_router/*=NULL*/;
/** Global router plugin list */
//extern GSList *router_list/*=NULL*/;
/** Router login blocked shield */
//extern gboolean router_login_blocked/*=FALSE*/;

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
		// aus router_info
//  gchar *host;
//	gchar *user;
//	gchar *password;
	gchar *name;
	gchar *version;
	gchar *serial;
	gchar *session_id;
	gchar *lang;
	gchar *annex;

	// neu erfunden
	int controller;
	int tamstick;
	int port;
	gchar *faxpfad;
	string faxheader;
	string faxmsn;
	string faxident;
	string faxvolume;
	vector<string> numbers;
	vector<string> phoneports;
	string countrycode;
	string internationalcallprefix;
	string areacode;
	string nationalcallprefix;
	string namedect;
	string nameanalog;
	string nameisdn;
	/* Extend */
	gint box_id;
	gint maj_ver_id;
	gint min_ver_id;
	GTimer *session_timer;
	// Ende router_info

  public:
    fbcl();
//    void fb_login_05_50();
		int FIRMWARE_IS(gint,gint);
		gboolean waehle(/*struct profile *profile, */gint port, const gchar *number);
		gboolean faxophone_connect_hier();
#ifdef false
  private:
    int fb_check_login_blocked();
	public:
    int loadj();
    int fb_get_settings_05_50();
    void fb_detect_controller_05_50();
		// in firmware-04-00.c
		gboolean fritzbox_login_04_00(/*struct profile *profile*/);
		gboolean fritzbox_dial_number_04_00(/*struct profile *profile, */gint port, const gchar *number);
		gboolean fritzbox_hangup_04_00(/*struct profile *profile, */gint port, const gchar *number);
		gboolean fritzbox_present_04_00(/*struct router_info *router_info*/);
			//		gboolean router_login(struct profile *profile);
		// in fritzbox.c
		gboolean fritzbox_present(/*struct router_info *router_info*/);
		gboolean fritzbox_login(/*struct profile *profile*/);
		gboolean fritzbox_logout(/*struct profile *profile, */gboolean force);
		void fritzbox_read_msn(/*struct profile *profile, */const gchar *data);
		gboolean fritzbox_get_settings(/*struct profile *profile*/);
		// gboolean fritzbox_load_journal(struct profile *profile, gchar **data_ptr);
		gboolean fritzbox_dial_number(/*struct profile *profile, */gint port, const gchar *number);
		gboolean fritzbox_hangup(/*struct profile *profile, */gint port, const gchar *number);
//		GSList *fritzbox_load_faxbox(GSList *journal);
		gchar *fritzbox_load_fax(/*struct profile *profile, */const gchar *filename, gsize *len);
		gchar *fritzbox_get_ip(/*struct profile *profile*/);
		gboolean fritzbox_reconnect(/*struct profile *profile*/);
		gboolean fritzbox_delete_fax(/*struct profile *profile, */const gchar *filename);
		gboolean fritzbox_login_04_74(/*struct profile *profile*/);
		gboolean fritzbox_get_settings_04_74(/*struct profile *profile*/);
//		gboolean fritzbox_load_journal_04_74(/*struct profile *profile, */gchar **data_ptr);
//		gboolean fritzbox_clear_journal_04_74(/*struct profile *profile*/);
		gboolean fritzbox_login_05_50(/*struct profile *profile*/);
		gboolean fritzbox_get_settings_05_50(/*struct profile *profile*/);
//		void fritzbox_journal_cb(SoupSession *session, SoupMessage *msg, gpointer user_data);
//		gboolean fritzbox_load_journal_05_50(/*struct profile *profile, */gchar **data_ptr);
//		gboolean fritzbox_clear_journal_05_50(/*struct profile *profile*/);
		gboolean fritzbox_get_settings_06_35(/*struct profile *profile*/);
		gboolean fritzbox_dial_number_06_35(/*struct profile *profile, */gint port, const gchar *number);
		void fritzbox_detect_controller_06_35(/*struct profile *profile, */const gchar *data);
		gboolean fritzbox_hangup_06_35(/*struct profile *profile, */gint port, const gchar *number);
		void fritzbox_extract_phone_names_06_35(/*struct profile *profile, */const gchar *data, gsize read);
		gboolean fritzbox_get_settings_query(/*struct profile *profile*/);
		void fritzbox_detect_controller_05_50(/*struct profile *profile, */const gchar *data);
		void fritzbox_extract_dect_05_50(/*struct profile *profile, */const gchar *data);
		void router_set_phone_port(/*struct profile *profile, */gint _port);
		gint router_get_phone_port(/*struct profile *profile*/);
#endif
};
