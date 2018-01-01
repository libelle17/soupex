#!/bin/bash
curl -u libelle17:bach17rago \
-s "http://fritz.box:49000/igdupnp/control/WANIPConn1" \
-H "Content-Type: text/xml; charset="utf-8""  \
-H "SoapAction:urn:schemas-upnp-org:service:WANIPConnection:1#GetInfo" \
-d "@getinfo.xml"
