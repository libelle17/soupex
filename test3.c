/********* Sample code generated by the curl command line tool **********
 * All curl_easy_setopt() options are documented at:
 * http://curl.haxx.se/libcurl/c/curl_easy_setopt.html
 ************************************************************************/
#include <curl/curl.h>

int main(int argc, char *argv[])
{
  CURLcode ret;
  CURL *hnd;
  struct curl_slist *slist1;

  slist1 = NULL;
  slist1 = curl_slist_append(slist1, "Content-Type: text/xml; charset=\"utf-8\"");
  slist1 = curl_slist_append(slist1, "SoapAction: urn:dslforum-org:service:X_AVM-DE_OnTel:1#GetCallList");

  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_URL, "http://fritz.box:49000/upnp/control/x_contact");
  curl_easy_setopt(hnd, CURLOPT_USERPWD, "libelle17:bach17raga");
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"\nxmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\n<s:Body>\n<u:GetCallList xmlns:u=\"urn:dslforum-org:service:X_AVM-DE_OnTel:1\">\n<></>\n</u:GetCallList>\n</s:Body>\n</s:Envelope>");
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)287);
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.37.0");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANY);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(hnd, CURLOPT_IPRESOLVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);

  /* Here is a list of options the curl code used that cannot get generated
     as source easily. You may select to either not use them or implement
     them yourself.

  CURLOPT_WRITEDATA set to a objectpointer
  CURLOPT_WRITEFUNCTION set to a functionpointer
  CURLOPT_READDATA set to a objectpointer
  CURLOPT_READFUNCTION set to a functionpointer
  CURLOPT_SEEKDATA set to a objectpointer
  CURLOPT_SEEKFUNCTION set to a functionpointer
  CURLOPT_ERRORBUFFER set to a objectpointer
  CURLOPT_STDERR set to a objectpointer
  CURLOPT_HEADERFUNCTION set to a functionpointer
  CURLOPT_HEADERDATA set to a objectpointer

  */

  ret = curl_easy_perform(hnd);

  curl_easy_cleanup(hnd);
  hnd = NULL;
  curl_slist_free_all(slist1);
  slist1 = NULL;

  return (int)ret;
}
/**** End of sample code ****/
