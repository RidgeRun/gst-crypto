/*
 * GStCrypto
 * Copyright, LCC (C) 2015 RidgeRun, LCC <carsten.behling@ridgerun.com>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the
 * GNU Lesser General Public License Version 2.1 (the "LGPL"), in
 * which case the following provisions apply instead of the ones
 * mentioned above:
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1335, USA.
 */

/**
 * SECTION:gst-crypto
 *
 * FIXME:Describe gst-crypto here.
 *
 * <refsect2>
 * <title>Example launch line</title>
 * |[
 * gst-launch -v -m fakesrc ! crypto ! fakesink mode=enc cypher=aes-128-cbc key=cabecabecabecabe
 * ]|
 * </refsect2>
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gst/gst.h>
#include <gst/base/gstbasetransform.h>
#include <gst/controller/gstcontroller.h>

#include "gstcrypto.h"

#include <openssl/evp.h>

GST_DEBUG_CATEGORY_STATIC (gst_crypto_debug);
#define GST_CAT_DEFAULT gst_crypto_debug

/* Filter signals and args */
enum
{
  /* FILL ME */
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_MODE,
  PROP_CIPHER,
  PROP_KEY,
};

/* the capabilities of the inputs and outputs.
 *
 */
static GstStaticPadTemplate sink_template =
GST_STATIC_PAD_TEMPLATE (
  "sink",
  GST_PAD_SINK,
  GST_PAD_ALWAYS,
  GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate src_template =
GST_STATIC_PAD_TEMPLATE (
  "src",
  GST_PAD_SRC,
  GST_PAD_ALWAYS,
  GST_STATIC_CAPS ("ANY")
);

/* debug category for fltering log messages
 *
 * FIXME:exchange the string 'Template crypto' with your description
 */
#define DEBUG_INIT(bla) \
  GST_DEBUG_CATEGORY_INIT (gst_crypto_debug, "crypto", 0, "Template crypto");

GST_BOILERPLATE_FULL (GstCrypto, gst_crypto, GstBaseTransform,
    GST_TYPE_BASE_TRANSFORM, DEBUG_INIT);

static void gst_crypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec);
static void gst_crypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec);

static GstFlowReturn gst_crypto_transform_ip (GstBaseTransform * base,
    GstBuffer * outbuf);

static void gst_crypto_finalize (GObject *object);

/* GObject vmethod implementations */

static void
gst_crypto_base_init (gpointer klass)
{
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gst_element_class_set_details_simple (element_class,
    "Crypto",
    "Generic/Filter",
    "FIXME:Generic Template Filter",
    "Carsten Behling <<user@hostname.org>>");

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&src_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&sink_template));
}

/* initialize the crypto's class */
static void
gst_crypto_class_init (GstCryptoClass * klass)
{
  GObjectClass *gobject_class;

  gobject_class = (GObjectClass *) klass;
  gobject_class->set_property = gst_crypto_set_property;
  gobject_class->get_property = gst_crypto_get_property;

  g_object_class_install_property (gobject_class, PROP_MODE,
    g_param_spec_string ("mode", "Mode",
          "'enc' for encryption, 'dec' for decryption", "enc",
          G_PARAM_READWRITE));
  g_object_class_install_property (gobject_class, PROP_CIPHER,
    g_param_spec_string ("cipher", "Cipher",
          "cypher string in openssl format, currently aes-128-cbc only", "aes-128-cbc",
          G_PARAM_READWRITE));
  g_object_class_install_property (gobject_class, PROP_KEY,
    g_param_spec_string ("key", "Key",
          "crypto key as hex string", "cabecabecabecabe",
          G_PARAM_READWRITE));

  gobject_class->finalize = gst_crypto_finalize;

  GST_BASE_TRANSFORM_CLASS (klass)->transform_ip =
      GST_DEBUG_FUNCPTR (gst_crypto_transform_ip);
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad calback functions
 * initialize instance structure
 */
static void
gst_crypto_init (GstCrypto *filter, GstCryptoClass * klass)
{
  filter->mode = g_malloc (64);
  g_stpcpy (filter->mode, "enc");
  filter->cipher = g_malloc (64);
  g_stpcpy (filter->cipher, "aes-128-cbc");
  filter->key = g_malloc (64);  
  g_stpcpy (filter->key, "cabecabecabecabe");
}

static void
gst_crypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstCrypto *filter = GST_CRYPTO (object);

  switch (prop_id) {
    case PROP_MODE:
      filter->mode = g_value_dup_string (value);
      break;
    case PROP_CIPHER:
      filter->cipher = g_value_dup_string (value);
      break;
    case PROP_KEY:
      filter->key = g_value_dup_string (value);	 
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_crypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstCrypto *filter = GST_CRYPTO (object);

  switch (prop_id) {
    case PROP_MODE:
      g_value_set_string (value, filter->mode);
      break;
    case PROP_CIPHER:
      g_value_set_string (value, filter->cipher);
      break;
    case PROP_KEY:
	  g_value_set_string (value, filter->key);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

/* GstBaseTransform vmethod implementations */

/* this function does the actual processing
 */
static GstFlowReturn
gst_crypto_transform_ip (GstBaseTransform * base, GstBuffer * outbuf)
{
  GstCrypto *filter = GST_CRYPTO (base);

  if (GST_CLOCK_TIME_IS_VALID (GST_BUFFER_TIMESTAMP (outbuf)))
    gst_object_sync_values (G_OBJECT (filter), GST_BUFFER_TIMESTAMP (outbuf));

    g_print ("I'm plugged, therefore I'm in.\n");
  
  /* FIXME: do something interesting here.  This simply copies the source
   * to the destination. */

  return GST_FLOW_OK;
}

/* Object destructor
 */
static void
gst_crypto_finalize (GObject *object)
{
  GstCrypto *filter;

  filter= GST_CRYPTO(object);

  /* free up used heap */
  g_free (filter->mode);
  g_free (filter->cipher);
  g_free (filter->key);

  /* Chain up to the parent class */
  G_OBJECT_CLASS (parent_class)->finalize;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
crypto_init (GstPlugin * crypto)
{
  /* initialize gst controller library */
  gst_controller_init(NULL, NULL);

  return gst_element_register (crypto, "gst-crypto", GST_RANK_NONE,
      GST_TYPE_CRYPTO);
}

/* PACKAGE: this is usually set by autotools depending on some _INIT macro
 * in configure.ac and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use autotools to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "gst-crypto"
#endif
/* gstreamer looks for this structure to register cryptos
 *
 */
GST_PLUGIN_DEFINE (
    GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    PACKAGE,
    "RidgeRun encryption/decryption plugin",
    crypto_init,
    VERSION,
    "GPL",
    PACKAGE,
    "https://github.com/RidgeRun/gst-crypto"
)
