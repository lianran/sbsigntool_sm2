/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the OpenSSL
 * library under certain conditions as described in each individual source file,
 * and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 */
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <getopt.h>

#include <ccan/talloc/talloc.h>
#include <ccan/read_write_all/read_write_all.h>

#include "image.h"
#include "idc.h"
#include "fileio.h"

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

static const char *toolname = "sbverify";
static const int cert_name_len = 160;

enum verify_status {
	VERIFY_FAIL = 0,
	VERIFY_OK = 1,
};

static struct option options[] = {
	{ "cert", required_argument, NULL, 'c' },
	{ "no-verify", no_argument, NULL, 'n' },
	{ "detached", required_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options] --cert <certfile> <efi-boot-image>\n"
		"Verify a UEFI secure boot image.\n\n"
		"Options:\n"
		"\t--cert <certfile>  certificate (x509 certificate)\n"
		"\t--no-verify        don't perform certificate verification\n"
		"\t--detached <file>  read signature from <file>, instead of\n"
		"\t                    looking for an embedded signature\n",
			toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}



static int load_image_signature_data(struct image *image,
		uint8_t **buf, size_t *len)
{
	struct cert_table_header *header;

	if (!image->data_dir_sigtable->addr
			|| !image->data_dir_sigtable->size) {
		fprintf(stderr, "No signature table present\n");
		return -1;
	}

	header = (void *)image->buf + image->data_dir_sigtable->addr;
	*buf = (void *)(header + 1);
	*len = header->size - sizeof(*header);
	return 0;
}

static int load_detached_signature_data(struct image *image,
		const char *filename, uint8_t **buf, size_t *len)
{
	return fileio_read_file(image, filename, buf, len);
}

static int cert_in_store(X509 *cert, X509_STORE_CTX *ctx)
{
	X509_OBJECT obj;

	obj.type = X509_LU_X509;
	obj.data.x509 = cert;

	return X509_OBJECT_retrieve_match(ctx->ctx->objs, &obj) != NULL;
}
int  get_msg(struct image *image, unsigned char *msg, size_t *msglen)
{
	struct region *region;
	size_t i,n;
	n = 0;
	for (i = 0; i < (size_t) image->n_checksum_regions; i++){
		region = &image->checksum_regions[i];
		n += region->size;
	}
	*msglen = n;

	if(msg == NULL) return 1;

	n = 0;
	for(i = 0; i < (size_t) image->n_checksum_regions; i++){
		region = &image->checksum_regions[i];
		size_t j = 0;
		for(j = 0; j < (size_t) region->size; j++){
			uint8_t *buf;
			buf = region->data;
			msg[n+j] = (unsigned char) buf[j];
		}
		n += region->size;
	}
	return 1;
}

int main(int argc, char **argv)
{
	const char *detached_sig_filename, *image_filename, *certfilename;
	enum verify_status status;
	int rc, c, verify;
	struct image *image;
	X509 *cert;
	uint8_t *sig_buf;
	size_t sig_size;
	bool verbose;

	status = VERIFY_FAIL;
	verify = 1;
	verbose = false;
	detached_sig_filename = NULL;
	certfilename = NULL;

	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "c:d:nVh", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			certfilename = optarg;
			break;
		case 'd':
			detached_sig_filename = optarg;
			break;
		case 'n':
			verify = 0;
			break;
		case 'v':
			verbose = true;
			break;
		case 'V':
			version();
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		}

	}

	if (argc != optind + 1) {
		usage();
		return EXIT_FAILURE;
	}

	if(!verify){
		status = VERIFY_OK;
		goto end;
	}

	image_filename = argv[optind];

	image = image_load(image_filename);
	if (!image) {
		fprintf(stderr, "Can't open image %s\n", image_filename);
		return EXIT_FAILURE;
	}

	if (detached_sig_filename)
		rc = load_detached_signature_data(image, detached_sig_filename,
				&sig_buf, &sig_size);
	else
		rc = load_image_signature_data(image, &sig_buf, &sig_size);

	if (rc) {
		fprintf(stderr, "Unable to read signature data from %s\n",
				detached_sig_filename ? : image_filename);
		goto end;
	}

	const EVP_MD *md = EVP_sm3();
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char sig[256];
    unsigned int siglen = (unsigned int)sizeof(sig);
    unsigned char *msg;
    size_t msglen;

    /* get the signtext */
    size_t j;
    siglen = sig_size;
    for(j = 0; j < siglen; j++)
    {
    	sig[j] = (unsigned char)sig_buf[j];
    }
	if (verbose > 1) {
        size_t i;
        printf("signature (%u bytes) = ", siglen);
        for (i = 0; i < siglen; i++) {
            printf("%02X ", sig[i]);
        }
        printf("\n");
    }
    /* get the msg */
    get_msg(image, NULL, &msglen);
	msg = (unsigned char *)malloc(msglen);
	get_msg(image, msg, &msglen);


	/* init openssl global functions */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* get the pub key from the cert*/
    cert = fileio_read_cert(certfilename);
	pkey = X509_get_pubkey(cert);
	if(pkey == NULL){
        fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
        goto end;
    }

    /* verify the sign */
    if (!(mdctx = EVP_MD_CTX_create())) {
        fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
        goto end;
    }
    if (!EVP_VerifyInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
        goto end;
    }

    if (!EVP_VerifyUpdate(mdctx, msg, msglen)) {
        fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
        goto end;
    }

    if (EVP_VerifyFinal(mdctx, sig, siglen, pkey) != SM2_VERIFY_SUCCESS) {
        fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
        goto end;
    }

	status = VERIFY_OK;

end:
	talloc_free(image);
	EVP_MD_CTX_destroy(mdctx);
	if (status == VERIFY_OK)
		printf("Signature verification OK\n");
	else
		printf("Signature verification failed\n");

	return status == VERIFY_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
