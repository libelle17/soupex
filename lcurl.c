/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/ 
/* <DESC>
 * Get a web page, extract the title with libxml.
 * </DESC>

 Written by Lars Nilsson

 GNU C++ compile command line suggestion (edit paths accordingly):

 g++ -Wall -I/opt/curl/include -I/opt/libxml/include/libxml2 htmltitle.cpp -o htmltitle -L/opt/curl/lib -L/opt/libxml/lib -lcurl -lxml2
 */ 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <curl/curl.h>
#include <iostream>
#include <vector>

//
//  libcurl write callback function
//

static int writer(char *data, size_t size, size_t nmemb, std::string *writerData)
{
  if(writerData == NULL)
    return 0;

  writerData->append(data, size*nmemb);

  return size * nmemb;
}

size_t holraus(const std::string xml,std::string tag,std::string *ergp,size_t anf=0)
{
  const std::string von="<"+tag+">", bis="</"+tag+">";
  if (ergp) {
    ergp->clear();
    size_t p1=xml.find(von,anf);
    if (p1!=std::string::npos) {
      p1+=von.length();
      size_t p2=xml.find(bis,p1);
      if (p2!=std::string::npos) {
        *ergp=xml.substr(p1,p2-p1);
        return p2+bis.length();
      }
    }
  }
  return 0;
} // size_t holraus(const std::string xml,std::string tag,std::string *ergp;size_t anf=0)

// ermittelt aus test3.sh mit curl ... --libcurl test3.c
int fragurl(const std::string url, const std::string cred, const std::string servT, const std::string action,const std::string item, std::string* bufp)
{
  //std::cout<<"url: "<<url<<std::endl;
  CURL *hnd = NULL;
  CURLcode code;
  static char errorBuffer[CURL_ERROR_SIZE];
  bufp->clear();
  struct curl_slist *slist1=0;
  slist1 = curl_slist_append(slist1, "Content-Type: text/xml; charset=\"utf-8\"");
  slist1 = curl_slist_append(slist1, ("SoapAction: "+servT+"#"+action).c_str());
  hnd = curl_easy_init();
  if(hnd == NULL) {
    fprintf(stderr, "Failed to create CURL connection\n");
    exit(EXIT_FAILURE);
  }
  curl_easy_setopt(hnd, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hnd, CURLOPT_USERPWD, cred.c_str());
  std::string postfield="<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"\nxmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\n<s:Body>\n<u:"+action+" xmlns:u=\""+servT+"\">\n<></>\n</u:"+action+">\n</s:Body>\n</s:Envelope>";
  if ((code=curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, postfield.c_str()))!=CURLE_OK) {
    fprintf(stderr, "Fehler bei postfield [%s]\n", errorBuffer);
    return false;
  }
  curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)postfield.length());
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.37.0");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(hnd, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANY);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(hnd, CURLOPT_IPRESOLVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writer);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA , bufp);
  curl_easy_setopt(hnd, CURLOPT_ERRORBUFFER, errorBuffer);
  // Retrieve content for the URL
  code = curl_easy_perform(hnd);
  curl_easy_cleanup(hnd);
  if(code != CURLE_OK) {
    fprintf(stderr, "Fehler beim Verbinden zu '%s' [%s]\n", url.c_str(), errorBuffer);
    exit(EXIT_FAILURE);
  }
  return 0;
} // string fragurl(const string url, const string cred, const string servT, const string action,const string item)

int holurl(const std::string url, std::string* bufp)
{
  //std::cout<<"url: "<<url<<std::endl;
  CURL *hnd = NULL;
  CURLcode code;
  static char errorBuffer[CURL_ERROR_SIZE];
  bufp->clear();
  hnd = curl_easy_init();
  if(hnd == NULL) {
    fprintf(stderr, "Failed to create CURL connection\n");
    exit(EXIT_FAILURE);
  }
  curl_easy_setopt(hnd, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writer);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA , bufp);
  curl_easy_setopt(hnd, CURLOPT_ERRORBUFFER, errorBuffer);
  // Retrieve content for the URL
  code = curl_easy_perform(hnd);
  curl_easy_cleanup(hnd);
  if(code != CURLE_OK) {
    fprintf(stderr, "Fehler beim Verbinden zu '%s' [%s]\n", url.c_str(), errorBuffer);
    exit(EXIT_FAILURE);
  }
  return 0;
} // int holurl(const std::string url, std::string* bufp)

class anruf
{
  public:
  std::string id; //Id
  std::string type; //Type
  std::string caller; //Caller
  std::string called; //Called
  std::string callednumber; //CalledNumber
  std::string name; //Name
};

int main(int argc, char *argv[])
{
  std::vector<std::string> tz;
  tz.push_back("Id");
  tz.push_back("Type");
  tz.push_back("Caller");
  tz.push_back("Called");
  tz.push_back("CalledNumber");
  tz.push_back("Name");
  tz.push_back("Numbertype");
  tz.push_back("Device");
  tz.push_back("Port");
  tz.push_back("Date");
  tz.push_back("Duration");
  tz.push_back("Count");

  // Ensure one argument is given


  curl_global_init(CURL_GLOBAL_DEFAULT);

  // Initialize CURL connection

  std::string credentials="libelle17:bach17raga";
  std::string FB="fritz.box:49000";
  std::string controlURL="/upnp/control/x_contact";
  std::string serviceType="urn:dslforum-org:service:X_AVM-DE_OnTel:1";
  std::string action="GetCallList";
  std::string item="NewCallListURL";
  /*
  if(!init(hnd, ("http://"+FB+controlURL).c_str())) {
    fprintf(stderr, "Connection initializion failed\n");
    exit(EXIT_FAILURE);
  }
  */
  std::string buffer,nurl;
  fragurl("http://"+FB+controlURL,credentials,serviceType,action,item,&buffer);

  //std::cout<<buffer<<std::endl;
  holraus(buffer,item,&nurl);
  holurl(nurl,&buffer);
  size_t pos=0,enr=0;
  while ((pos=holraus(buffer,"Call",&nurl,pos))) {
    std::cout<<++enr<<": ";
    for(size_t tzn=0;tzn<tz.size();tzn++) {
      std::string it;
      holraus(nurl,tz[tzn],&it);
      std::cout<<it<<";";
    }
    std::cout<<std::endl;
  }

  // std::cout<<buffer<<std::endl;

  // Parse the (assumed) HTML code
  //  parseHtml(buffer, title);

  return EXIT_SUCCESS;
}
