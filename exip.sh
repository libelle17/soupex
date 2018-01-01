#!/bin/bash
curl -s "http://fritz.box:49000/igdupnp/control/WANIPConn1" -H "Content-Type: text/xml; charset="utf-8"" -H "SoapAction:urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress" -d "@exip.xml" | grep -Eo "\<[[:digit:]]{1,3}(\.[[:digit:]]{1,3}){3}\>"
