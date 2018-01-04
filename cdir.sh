#!/bin/bash
#GLIB_LIBS = -lgio-2.0 -lgobject-2.0 -lglib-2.0 
#GTKDOC_DEPS_LIBS = -lgobject-2.0 -lglib-2.0 
#INTROSPECTION_LIBS = -lgirepository-1.0 -lgobject-2.0 -lglib-2.0 
#KRB5_LIBS = -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
#SQLITE_LIBS = -lsqlite3 
#XML_LIBS = -lxml2 
#pkg-config --cflags --libs gtk+-2.0
  #/home/schade/rogerj/wand/libroutermanager/libroutermanager_la-fax_phone.o \
	#/home/schade/rogerj/wand/libroutermanager/libfaxophone/libroutermanager_la-faxophone.o \
	#/home/schade/rogerj/wand/libroutermanager/libfaxophone/libroutermanager_la-phone.o \
	#/home/schade/rogerj/wand/libroutermanager/libfaxophone/libroutermanager_la-fax.o \
	#/home/schade/rogerj/wand/libroutermanager/libfaxophone/libroutermanager_la-sff.o \
	#/home/schade/autofax/capi20_copy/libcapi20_la-capi20.o \
	#/home/schade/autofax/capi20_copy/libcapi20dyn.a \
	#/home/schade/rogerj/wand/libroutermanager/libfaxophone/.libs/libroutermanager_la-faxophone.o \
F=direkt; g++ $F.c \
  -I/home/schade/rogerj/wand \
  -I/home/schade/rogerj/wand/libroutermanager \
	/home/schade/rogerj/wand/libroutermanager/libfaxophone/faxophone.c \
	/home/schade/rogerj/wand/libroutermanager/libfaxophone/phone.c \
	/home/schade/rogerj/wand/libroutermanager/libfaxophone/fax.c \
	/home/schade/rogerj/wand/libroutermanager/audio.c \
	/home/schade/rogerj/wand/libroutermanager/logging.c \
	/home/schade/rogerj/wand/libroutermanager/appobject-emit.c \
	/home/schade/rogerj/wand/libroutermanager/libfaxophone/sff.c \
	/home/schade/rogerj/wand/libroutermanager/libfaxophone/isdn-convert.c \
	/home/schade/autofax/capi20_copy/libcapi20_la-capifunc.o \
	/home/schade/rogerj/wand/libroutermanager/.libs/libroutermanager.so.0.0.0 \
	/home/schade/autofax/capi20_copy/.libs/libcapi20.a \
  $(pkg-config --cflags --libs libsoup-2.4) \
	-ltiff -lspandsp -lrt -ldl -lsndfile \
	-o$F \
  >fehler 2>&1 \
  &&{ ./$F;:;} \
  ||vim +2 fehler
