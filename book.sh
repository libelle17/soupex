#!/bin/bash
wget --user='libelle17' --password='bach17raga' 'http://192.168.178.1:49000/upnp/control/x_contact' --header 'Content-Type: text/xml; charset="utf-8"' --header 'SoapAction:urn:dslforum-org:service:X_AVM-DE_OnTel:1#GetCallList' --post-file='book.xml'
