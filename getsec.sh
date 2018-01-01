#!/bin/bash
curl "http://fritz.box:49000" -H "POST:/igdupnp/control/deviceinfo HTTP/1.1" -H "Content-Type: text/xml; charset="utf-8"" -H "SoapAction:urn:urn:dslforum-org:service:DeviceInfo:1#GetSecurityPort" -d "@getsec.xml" 
