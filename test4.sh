#!/bin/bash

function docurl() {
dcerg=$(curl -4 -k --anyauth -u "${credentials}"                                    \
  "http://${FB}$controlURL"                                     \
  -H 'Content-Type: text/xml; charset="utf-8"'                           \
  -H 'SoapAction: '$serviceType'#'$action \
  -d '<?xml version="1.0" encoding="utf-8"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:'$action' xmlns:u="'$serviceType'">
<'$in1name'>'${in1val}'</'$in1name'>
</u:'$action'>
</s:Body>
</s:Envelope>' 2>/dev/null|([ -n "$item" ]&&sed '/'$item'/!d;s/.*<'$item'>\(.*\)<\/'$item'>.*/\1/'||cat))
}

credentials="libelle17:bach17raga"
FB="fritz.box:49000"
controlURL="/upnp/control/x_tam";
serviceType="urn:dslforum-org:service:X_AVM-DE_TAM:1";
action="GetInfo";
in1name="NewIndex";
in1val="0";
item="";
docurl;
echo ""
echo "$dcerg"

# netcat -4 fritz.box 1012
