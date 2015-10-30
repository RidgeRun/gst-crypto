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
 * SECTION:crypto
 *
 * FIXME:Describe crypto here.
 *
 * <refsect2>
 * <title>Example launch line</title>
 * |[
 * echo "This is a crypto test ... " > plain.txt && gst-launch  filesrc \
 *     location=plain.txt ! crypto mode=enc ! gst-crypto mode=dec ! \
 *     filesink location=dec.txt && cat dec.txt
 *
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

GST_DEBUG_CATEGORY_STATIC (gst_crypto_debug);
#define GST_CAT_DEFAULT gst_crypto_debug

#define DEFAULT_PASS "RidgeRun"
#define DEFAULT_KEY "1f9423681beb9a79215820f6bda73d0f"
#define DEFAULT_IV "e9aa8e834d8d70b7e0d254ff670dd718"

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
  PROP_PASS,
  PROP_KEY,
  PROP_IV,
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

static GstFlowReturn gst_crypto_transform (GstBaseTransform * base,
    GstBuffer * inbuf, GstBuffer * outbuf);
/* We have a bigger output buffer than input buffer and have to report that */
static gboolean gst_crypto_transform_size (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * incaps, guint insize,
    GstCaps * outcaps, guint * outsize);

static gboolean gst_crypto_start (GstBaseTransform * base);
static gboolean gst_crypto_stop (GstBaseTransform * base);

static void gst_crypto_finalize (GObject *object);

/* crypto helper functions */
static gboolean gst_crypto_openssl_init(GstCrypto *filter);
static GstFlowReturn gst_crypto_run(GstCrypto *filter);
static gboolean gst_crypto_pass2keyiv(GstCrypto *filter);

/* general helper functions */
static gboolean gst_crypto_hexstring2number(const gchar *in, gchar *out);

/* GObject vmethod implementations */

static void
gst_crypto_base_init (gpointer klass)
{
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gst_element_class_set_details_simple (element_class,
    "Crypto",
    "Generic/Filter",
    "RidgeRun's crypto plugin that encrypts/decrypts data on the fly",
    "Carsten Behling <carsten.behling@ridgerun.com>");

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
  g_object_class_install_property (gobject_class, PROP_PASS,
    g_param_spec_string ("pass", "Pass",
          "crypto password", DEFAULT_PASS,
          G_PARAM_READWRITE));
  /* The default hexkey is what openssl would generate from the default password
     'RidgeRun'*/
  g_object_class_install_property (gobject_class, PROP_KEY,
    g_param_spec_string ("key", "Key",
          "crypto hexkey", (guchar*)DEFAULT_KEY,
          G_PARAM_READWRITE));
  /* The default iv is what openssl would generate from the default password
     'RidgeRun'*/
  g_object_class_install_property (gobject_class, PROP_IV,
    g_param_spec_string ("iv", "Iv",
          "crypto initialization vector", (guchar*)DEFAULT_IV,
          G_PARAM_READWRITE));

  gobject_class->finalize = gst_crypto_finalize;

  GST_BASE_TRANSFORM_CLASS (klass)->transform =
      GST_DEBUG_FUNCPTR (gst_crypto_transform);
  GST_BASE_TRANSFORM_CLASS (klass)->transform_size =
      GST_DEBUG_FUNCPTR (gst_crypto_transform_size);
  GST_BASE_TRANSFORM_CLASS (klass)->start =
      GST_DEBUG_FUNCPTR (gst_crypto_start);
  GST_BASE_TRANSFORM_CLASS (klass)->stop =
      GST_DEBUG_FUNCPTR (gst_crypto_stop);
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad calback functions
 * initialize instance structure
 */
static void
gst_crypto_init (GstCrypto *filter, GstCryptoClass * klass)
{
  GST_LOG ("Initializing plugin");
  filter->mode = g_malloc (64);
  g_stpcpy (filter->mode, "enc");
  filter->is_encrypting = TRUE;
  filter->cipher = g_malloc (64);
  g_stpcpy (filter->cipher, "aes-128-cbc");
  filter->pass = g_malloc (64);  
  g_stpcpy (filter->pass, DEFAULT_PASS);
  filter->key = g_malloc (64);  
  filter->iv = g_malloc (64);
  filter->use_pass = TRUE;
  GST_LOG ("Plugin initialization successfull");
}

static void
gst_crypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstCrypto *filter = GST_CRYPTO (object);

  GST_LOG ("Setting properties");
  switch (prop_id) {
    case PROP_MODE:
      filter->mode = g_value_dup_string (value);
      if (!g_strcmp0(filter->mode, "enc"))
        filter->is_encrypting = TRUE;
      else if(!g_strcmp0(filter->mode, "dec"))
        filter->is_encrypting = FALSE;
      break;
    case PROP_CIPHER:
      filter->cipher = g_value_dup_string (value);
      filter->evp_cipher = EVP_get_cipherbyname(filter->cipher);
      break;
    case PROP_PASS:
      filter->pass = g_value_dup_string (value);
	  filter->use_pass = TRUE;
      break;
    case PROP_KEY:
      if(!gst_crypto_hexstring2number(g_value_dup_string (value),
          (gchar*)filter->key)) {
        /* If hexkey is invalid, set to default */
		gst_crypto_hexstring2number(DEFAULT_KEY, (gchar*)filter->key);
	  }
	  filter->use_pass = FALSE;
      break;
    case PROP_IV:
      if(!gst_crypto_hexstring2number(g_value_dup_string (value),
          (gchar*)filter->iv)) {
        /* If hexkey is invalid, set to default */
		gst_crypto_hexstring2number(DEFAULT_IV, (gchar*)filter->iv);
	  }
	  filter->use_pass = FALSE;
      break;
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
  GST_LOG ("mode: %s", filter->mode);
  GST_LOG ("cipher: %s", filter->cipher);
  GST_LOG ("pass: %s", filter->pass);
  GST_LOG ("Set properties succsessfully ");
}

static void
gst_crypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstCrypto *filter = GST_CRYPTO (object);

  GST_LOG ("Getting properties");
  switch (prop_id) {
    case PROP_MODE:
      g_value_set_string (value, filter->mode);
      break;
    case PROP_CIPHER:
      g_value_set_string (value, filter->cipher);
      break;
    case PROP_PASS:
	  g_value_set_string (value, filter->pass);
      break;
    case PROP_KEY:
	  g_value_set_string (value, (gchar*)filter->key);
      break;
    case PROP_IV:
	  g_value_set_string (value, (gchar*)filter->iv);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
  GST_LOG ("Got properties succsessfully ");
}

/* GstBaseTransform vmethod implementations */

/* this function does the actual processing
 */
static GstFlowReturn
gst_crypto_transform (GstBaseTransform * base,
    GstBuffer * inbuf, GstBuffer * outbuf)
{
  GstCrypto *filter = GST_CRYPTO (base);
  GstFlowReturn ret;

  GST_LOG ("Transforming, input buffer size %d, output buffer size: %d\n",
      GST_BUFFER_SIZE (inbuf), GST_BUFFER_SIZE (outbuf));

  if (GST_CLOCK_TIME_IS_VALID (GST_BUFFER_TIMESTAMP (outbuf)))
    gst_object_sync_values (G_OBJECT (filter), GST_BUFFER_TIMESTAMP (outbuf));

  if (!GST_BUFFER_DATA (inbuf) || !GST_BUFFER_DATA (outbuf))
    return GST_FLOW_ERROR;

  if (filter->is_encrypting) {
    filter->plaintext = GST_BUFFER_DATA (inbuf);
    filter->plaintext_len = GST_BUFFER_SIZE (inbuf);
    filter->ciphertext = GST_BUFFER_DATA (outbuf);
  } else {
    filter->plaintext = GST_BUFFER_DATA (outbuf);
    filter->ciphertext = GST_BUFFER_DATA (inbuf);
    filter->ciphertext_len = GST_BUFFER_SIZE (inbuf);
  }
  ret = gst_crypto_run(filter);
  if (filter->is_encrypting) {
    GST_BUFFER_SIZE (outbuf) = filter->ciphertext_len;
  } else {
    GST_BUFFER_SIZE (outbuf) = filter->plaintext_len;
  }
  GST_LOG ("Plaintext len: %d, Ciphertext len: %d", filter->plaintext_len,
      filter->ciphertext_len);
  GST_LOG ("Transformation successfull");
  return ret;
}

static gboolean
gst_crypto_transform_size (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * incaps, guint insize,
    GstCaps * outcaps, guint * outsize)
{
  GstCrypto *filter = GST_CRYPTO (base);
  gboolean ret = TRUE;

  GST_LOG ("Transforming size");

  /* Encrypted text may be bigger */
  if(filter->is_encrypting)
  	*outsize = insize += EVP_MAX_BLOCK_LENGTH;
  else
  	*outsize = insize;

  return ret;
}

static gboolean
gst_crypto_start (GstBaseTransform * base)
{
  GstCrypto *filter = GST_CRYPTO (base);
  GST_LOG ("Starting");

  if(!gst_crypto_openssl_init(filter)) {
    GST_ERROR ("Openssl initialization failed");
    return FALSE;
  }

  if(filter->use_pass)
    if(!gst_crypto_pass2keyiv(filter)) {
      GST_ERROR ("Openssl key and iv generation failed");
      return FALSE;
    }

  GST_LOG ("Start successfull");
  return TRUE;
}

static gboolean
gst_crypto_stop (GstBaseTransform * base)
{
  GST_LOG ("Stopping");
  GST_LOG ("Stop successfull");
  return TRUE;
}

/* Crypto helper  functions */
static gboolean
gst_crypto_openssl_init(GstCrypto *filter)
{
  GST_LOG ("Initializing");

  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
  filter->evp_cipher = EVP_get_cipherbyname(filter->cipher);
  if(!filter->evp_cipher) {
    GST_ERROR ("Could not get cipher by name from openssl");
    return FALSE;
  }
  filter->evp_md = EVP_get_digestbyname("md5");
  if(!filter->evp_md) {
    GST_ERROR ("Could not get md5 digest by name from openssl");
    return FALSE;
  }
  filter->salt = NULL;
  GST_LOG ("Initialization successfull");
  return TRUE;
}

static GstFlowReturn
gst_crypto_run(GstCrypto *filter)
{
  GstFlowReturn ret = GST_FLOW_OK;
  EVP_CIPHER_CTX *ctx;
  int len;

  GST_LOG ("Crypto running");
  if(!(ctx = EVP_CIPHER_CTX_new()))
    return GST_FLOW_ERROR;

  if (filter->is_encrypting) {
    GST_LOG ("Encrypting");
    if(1 != EVP_EncryptInit_ex(ctx, filter->evp_cipher, NULL, filter->key,
        filter->iv)) {
      GST_ERROR ("Could not initialize openssl encryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    if(1 != EVP_EncryptUpdate(ctx, filter->ciphertext, &len, filter->plaintext,
        filter->plaintext_len)) {
      GST_ERROR ("Could not update openssl encryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    filter->ciphertext_len = len;

    /* CBC means the last block is the new iv */
    /* FIXME: Can't libssl handle this transparently? */
    if(len >= filter->plaintext_len) {
      memcpy(filter->iv, filter->ciphertext + filter->ciphertext_len - 16, 16);
      goto crypto_run_out;
    }

    if(1 != EVP_EncryptFinal_ex(ctx, filter->ciphertext + len, &len)) {
      GST_ERROR ("Could not finalize openssl encryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    filter->ciphertext_len += len;
  } else {
    GST_LOG ("Decrypting");
    if(1 != EVP_DecryptInit_ex(ctx, filter->evp_cipher, NULL, filter->key,
        filter->iv)) {
      GST_ERROR ("Could not initialize openssl decryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    if(1 != EVP_DecryptUpdate(ctx, filter->plaintext, &len, filter->ciphertext,
        filter->ciphertext_len)) {
      GST_ERROR ("Could not update openssl decryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    filter->plaintext_len = len;

    /* CBC means the last block is the new iv */
    if(len == filter->ciphertext_len - 16) {
      memcpy(filter->iv, filter->ciphertext + len, 16);
      filter->plaintext_len += 16;
      goto crypto_run_out;
    }

    if(1 != EVP_DecryptFinal_ex(ctx, filter->plaintext + len, &len)) {
      GST_ERROR ("Could not finalize openssl decryption");
      ret = GST_FLOW_ERROR;
      goto crypto_run_out;
    }
    filter->plaintext_len += len;
  }
  GST_LOG ("Crypto run successfull");

crypto_run_out:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

static gboolean
gst_crypto_pass2keyiv(GstCrypto *filter)
{
  GST_LOG ("Coverting pass to key/iv");
  if(!EVP_BytesToKey(filter->evp_cipher, filter->evp_md, filter->salt,
      (guchar*)filter->pass, strlen(filter->pass), 1, (guchar*)filter->key,
      (guchar*)filter->iv)) {
    GST_ERROR ("Could not execute openssl key/iv conversion");
    return FALSE;
  }
  GST_LOG ("Key/iv conversion successfull");
  return TRUE;
}

/* General helper functions */
static gboolean
gst_crypto_hexstring2number(const gchar *in, gchar *out)
{
  GST_LOG ("Coverting hex string to number");
  gchar byte_val;
  if(!in || !out)
    return FALSE;

  while(*in != 0) {
	/* Compute fist half-byte */
    if(*in >= 'A' && *in <= 'F') {
      byte_val = (*in - 55)<<4;
	} else if(*in >= 'a' && *in <= 'f') {
      byte_val = (*in - 87)<<4;
	} else if(*in >= '0' && *in <= '9') {
      byte_val = (*in - 48)<<4;
    } else {
      return FALSE;
    }
    in++;
    if(*in == 0) {
		break;
	}
    /* Compute second half-byte */
    if(*in >= 'A' && *in <= 'F') {
      *out = (*in - 55) + byte_val;
	} else if(*in >= 'a' && *in <= 'f') {
      *out = (*in - 87) + byte_val;
	} else if(*in >= '0' && *in <= '9') {
      *out = (*in - 48) + byte_val;
    } else {
      return FALSE;
    }

    GST_LOG ("ch: %c%c, hex: 0x%x", *(in-1),*in, *out);
    in++; out++;
    if(!in || !out)
      return FALSE;
  }
  GST_LOG ("Hex string conversion successfull");

  return TRUE;
}

/* Object destructor
 */
static void
gst_crypto_finalize (GObject *object)
{
  GstCrypto *filter;

  GST_LOG ("Finalizing");
  filter= GST_CRYPTO(object);

  /* free up used heap */
  if(filter->mode)
    g_free (filter->mode);
  if(filter->cipher)
    g_free (filter->cipher);
  if(filter->pass)
    g_free (filter->pass);
  if(filter->key)
    g_free (filter->key);
  if(filter->iv)
    g_free (filter->iv);
  GST_LOG ("Finalization successfull");
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

  return gst_element_register (crypto, "crypto", GST_RANK_NONE,
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
    "LGPL",
    "crypto",
    "https://github.com/RidgeRun/gst-crypto"
)
