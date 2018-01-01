#!/bin/bash

NETCAT=`which netcat`
[ -z "$NETCAT" ] && NETCAT=`which nc`
[ -z "$NETCAT" ] && exit 1

INTERFACE_NS="urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"
WANIP_NS="urn:schemas-upnp-org:service:WANIPConnection:1"

if [ "$1" = "-ip" ]; then
NS="$WANIP_NS"
REQUEST="GetExternalIPAddress"
SED='/^<NewExternalIP/ s,</\?NewExternalIPAddress>,,gp'
else
NS="$INTERFACE_NS"
REQUEST="GetAddonInfos"
if [ "$1" = "-a" ]; then
SED='s,<New,<, ; /^<[a-zA-Z]*[ >]/ s,^<\([^> ]*\) *>\([^<]*\)</.*,\1\t\2,p'
else
SED='s/Send/OUT/ ; s/Receive/IN/ ; /^<NewByte/ s,^<NewByte\([^>]*\)Rate>\([^<]*\)<.*,\1\t\2,gp'
fi
fi

( $NETCAT 192.168.178.1 49000 | sed -ne "$SED" ) <<EOF
POST /upnp/control/WANCommonIFC1 HTTP/1.1
Content-Type: text/xml; charset="utf-8"
HOST: 192.168.178.1:49000
Content-Length: 0
SOAPACTION: "$NS#$REQUEST"

<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:$REQUEST xmlns:u=$NS /></s:Body>
</s:Envelope>
EOF
