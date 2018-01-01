#!/bin/bash
#GLIB_LIBS = -lgio-2.0 -lgobject-2.0 -lglib-2.0 
#GTKDOC_DEPS_LIBS = -lgobject-2.0 -lglib-2.0 
#INTROSPECTION_LIBS = -lgirepository-1.0 -lgobject-2.0 -lglib-2.0 
#KRB5_LIBS = -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
#SQLITE_LIBS = -lsqlite3 
#XML_LIBS = -lxml2 
#pkg-config --cflags --libs gtk+-2.0
F=direkt; g++ $F.c -o$F \
  $(pkg-config --cflags --libs libsoup-2.4) \
  >fehler 2>&1 \
  &&{ ./$F;:;} \
  ||vim +2 fehler
