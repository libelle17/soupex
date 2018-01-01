#!/bin/bash
# Telefonbuch der Fritzbox in XML-Datei auslesen
set -x
# PATH=/usr:/usr/bin:/bin
ziel_pfad=/root
ziel_datei=FRITZ.xml

# FritzBox credentials
_FBOX="fritz.box"
Passwd="bach17raga"
_PhonebookId="0"
_PhonebookExportName="Telefonbuch"

# get challenge key from FB
Challenge=`wget -O - "http://${_FBOX}/login_sid.lua" 2>/dev/null | sed 's/.*<Challenge>\(.*\)<\/Challenge>.*/\1/'`

# login aufbauen und hashen
CPSTR="$Challenge-$Passwd"
MD5=`echo -n $CPSTR | iconv -f ISO8859-1 -t UTF-16LE | md5sum -b | awk '{print substr($0,1,32)}'`
RESPONSE="$Challenge-$MD5"
POSTDATA="?username=&response=$RESPONSE"

# login senden und SID herausfischen
_SID=`wget -O - --post-data="$POSTDATA" "http://${_FBOX}/login_sid.lua" 2>/dev/null | sed 's/.*<SID>\(.*\)<\/SID>.*/\1/'`

# get configuration from FB and write to STDOUT
curl -s \
  -k \
  --form 'sid='${_SID} \
  --form 'PhonebookId='${_PhonebookId} \
  --form 'PhonebookExportName='${_PhonebookExportName} \
  --form 'PhonebookExport=' \
  http://${_FBOX}/cgi-bin/firmwarecfg \
  -o ${ziel_pfad}/${ziel_datei}
