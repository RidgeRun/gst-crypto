plugin_LTLIBRARIES = libgstcrypto.la

libgstcrypto_la_SOURCES = gstcrypto.c gstcrypto.h

libgstcrypto_la_CFLAGS = $(GST_CFLAGS) $(OPENSSL_CFLAGS)
libgstcrypto_la_LIBADD = $(GST_LIBS) $(OPENSSL_LIBS)
libgstcrypto_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS)
libgstcrypto_la_LIBTOOLFLAGS = --tag=disable-static

noinst_HEADERS = gstcrypto.h
