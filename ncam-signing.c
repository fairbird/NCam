#define MODULE_LOG_PREFIX "signing"

#include "globals.h"
#include "ncam-signing.h"
#include "cscrypt/sha256.h"
#include "ncam-string.h"
#include "ncam-time.h"
#include "ncam-files.h"

#ifndef CERT_ALGO_RSAENCRYPTION // warning about using OpenSSL versions before 1.0.0 with non RSA public key algorithm
#if OPENSSL_VERSION_NUMBER < 0x10000000L
#pragma message "WARNING: Due to lack of full support for elliptic curve signature algorithms in OpenSSL versions before 1.0.0, \
make sure using RSA public key algorithm. Otherwise binary signature validation at runtime will not work!"
#endif
#endif

extern char *config_cert;
struct o_sign_info osi;

static char* _X509_NAME_oneline_utf8(X509_NAME *name)
{
	if (!name)
		return NULL;

	BIO *bio_out = BIO_new(BIO_s_mem());
	if (!bio_out)
		return NULL;

	// Ensure buffer is updated and readable
	X509_NAME_print_ex(bio_out, name, 0,
		(ASN1_STRFLGS_RFC2253 | XN_FLAG_SEP_COMMA_PLUS |
		 XN_FLAG_FN_SN | XN_FLAG_DUMP_UNKNOWN_FIELDS) & ~ASN1_STRFLGS_ESC_MSB);

	(void)BIO_flush(bio_out);

	BUF_MEM *bio_buf = NULL;
	BIO_get_mem_ptr(bio_out, &bio_buf);
	if (!bio_buf || !bio_buf->data || bio_buf->length == 0)
	{
		BIO_free(bio_out);
		return NULL;
	}

	char *line = (char *)malloc(bio_buf->length + 1);
	if (!line)
	{
		BIO_free(bio_out);
		return NULL;
	}

	memcpy(line, bio_buf->data, bio_buf->length);
	line[bio_buf->length] = '\0';

	BIO_free(bio_out);
	return line;
}

static void hex_encode(const unsigned char* readbuf, void *writebuf, size_t len)
{
	char *out = (char *)writebuf;
	size_t i;

	for(i=0; i < len; i++)
	{
		/* 3 = two hex digits + null terminator (overwritten next iteration) */
		snprintf(out + (i * 2), 3, "%02x", readbuf[i]);
	}

	out[len * 2] = '\0';
}

static time_t posix_time(unsigned int year, unsigned int month, unsigned int day,
						 unsigned int hour, unsigned int min, unsigned int sec)
{
	if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
		hour > 23 || min > 59 || sec > 60)
	{
		return -1;
	}

	// Cumulative days to month (non-leap years)
	static const unsigned int month_day[13] = {0, 0, 31, 59, 90, 120, 151, 181,
											   212, 243, 273, 304, 334};
	unsigned int full_year = year;
	year -= 1900;

	// Leap-year correction
	bool is_leap = (full_year % 4 == 0 && (full_year % 100 != 0 || full_year % 400 == 0));
	unsigned int leap_correction = (is_leap && month > 2) ? 1 : 0;

	// Number of Februaries since 1900
	const unsigned int year_for_leap = (month > 2) ? year + 1 : year;

	return (time_t)(
		sec + min * 60 + hour * 3600 +
		(month_day[month] + day - 1 + leap_correction) * 86400 +
		(year - 70) * 31536000 +
		((year_for_leap - 69) / 4) * 86400 -
		((year_for_leap - 1) / 100) * 86400 +
		((year_for_leap + 299) / 400) * 86400
	);
}

static unsigned int two_digits_to_uint(const char **s) {
	unsigned int n = 10 * (**s - '0');
	(*s)++;
	n += (**s - '0');
	(*s)++;
	return n;
}

static time_t ASN1_TIME_to_posix_time(const ASN1_TIME *t) {
	if (!t) return -1;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L  // changed in OpenSSL 1.1.0+
	const unsigned char *us = ASN1_STRING_get0_data((const ASN1_STRING*)t);
	const char *s = (const char*)us;
#else
	const char *s = (const char*)t->data;
#endif
	if (!s) return -1;

	unsigned int year, month, day, hour, min, sec;
	switch(t->type) // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1
	{
		case V_ASN1_UTCTIME: // YYMMDDHHMMSSZ
			year = two_digits_to_uint(&s);
			year += year < 50 ? 2000 : 1900;
			break;
		case V_ASN1_GENERALIZEDTIME: // YYYYMMDDHHMMSSZ
			year = 100 * two_digits_to_uint(&s);
			year += two_digits_to_uint(&s);
			break;
		default:
			return -1; // error
	}
	month = two_digits_to_uint(&s);
	day   = two_digits_to_uint(&s);
	hour  = two_digits_to_uint(&s);
	min   = two_digits_to_uint(&s);
	sec   = two_digits_to_uint(&s);
	if (*s != 'Z') return -1;
	if (year == 9999 && month == 12 && day == 31 && hour == 23 && min == 59
		&& sec == 59) // 99991231235959Z rfc 5280
	{
		return -1;
	}
	return posix_time(year, month, day, hour, min, sec);
}

static void convert_ASN1TIME(const ASN1_TIME *t, char *buf, size_t len) {
	struct tm timeinfo;

	time_t ct = ASN1_TIME_to_posix_time(t);
	localtime_r(&ct, &timeinfo);
	strftime(buf, len, "%d.%m.%Y %H:%M:%S", &timeinfo);
}

static EVP_PKEY *verify_cert(void)
{
	int ret = 0;
	char system_ca_file[MAX_LEN];
	char ptype[MAX_LEN];
	X509 *pCert = NULL;
	BIO *pBio = NULL;
	EVP_PKEY *pKey = NULL;

	// Add all digest algorithms to the table
#if OPENSSL_VERSION_NUMBER < 0x30000000L // no-op in OpenSSL 3.0+
	OpenSSL_add_all_algorithms();
#endif

	pBio = BIO_new(BIO_s_mem());
	if (!pBio)
	{
		cs_log("Error: BIO_new() failed");
		return NULL;
	}

	// Load built-in cert from memory into BIO object
	if (!BIO_puts(pBio, config_cert))
	{
		cs_log("Error: BIO_puts() failed");
		BIO_free(pBio);
		return NULL;
	}

	// Read cert in PEM format from BIO (allocates X509 internally)
	pCert = PEM_read_bio_X509(pBio, NULL, NULL, NULL);
	if (!pCert)
	{
		cs_log("Error: PEM_read_bio_X509() failed");
		BIO_free(pBio);
		return NULL;
	}

	// version
	osi.cert_version = (int)X509_get_version(pCert) + 1;

	// valid from / to
	ASN1_TIME *not_before = X509_get_notBefore(pCert);
	convert_ASN1TIME(not_before, osi.cert_valid_from, sizeof(osi.cert_valid_from));
	ASN1_TIME *not_after = X509_get_notAfter(pCert);
	convert_ASN1TIME(not_after, osi.cert_valid_to, sizeof(osi.cert_valid_to));

	// expiration
	osi.cert_is_expired = !(X509_cmp_current_time(not_before) < 0 &&
							X509_cmp_current_time(not_after) > 0);

	// serial number
	ASN1_INTEGER *serial = X509_get_serialNumber(pCert);
	BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
	char *hex = BN_bn2hex(bn);
	osi.cert_serial = NULL;
	if (cs_malloc(&osi.cert_serial, cs_strlen(hex) + 1))
		cs_strncpy(osi.cert_serial, strtolower(hex), cs_strlen(hex) + 1);
	OPENSSL_free(hex);
	BN_free(bn);

	// fingerprint (SHA1)
	unsigned char buf[SHA_DIGEST_LENGTH];
	const EVP_MD *digest = EVP_sha1();
	unsigned len = 0;
	ret = X509_digest(pCert, digest, buf, &len);
	if (ret && len == SHA_DIGEST_LENGTH)
	{
		char strbuf[2 * SHA_DIGEST_LENGTH + 1];
		hex_encode(buf, strbuf, SHA_DIGEST_LENGTH);
		osi.cert_fingerprint = NULL;
		if (cs_malloc(&osi.cert_fingerprint, cs_strlen(strbuf) + 1))
			cs_strncpy(osi.cert_fingerprint, strtolower(strbuf), cs_strlen(strbuf) + 1);
	}

	// subject + issuer
	char *subj = _X509_NAME_oneline_utf8(X509_get_subject_name(pCert));
	char *issuer = _X509_NAME_oneline_utf8(X509_get_issuer_name(pCert));
	osi.cert_subject = NULL;
	osi.cert_issuer = NULL;
	if (cs_malloc(&osi.cert_subject, cs_strlen(subj) + 1))
		cs_strncpy(osi.cert_subject, subj, cs_strlen(subj) + 1);
	if (cs_malloc(&osi.cert_issuer, cs_strlen(issuer) + 1))
		cs_strncpy(osi.cert_issuer, issuer, cs_strlen(issuer) + 1);

	// self-signed check
	osi.cert_is_cacert = false;
	if (strncmp(subj, issuer, cs_strlen(issuer)) != 0)
		osi.cert_is_cacert = true;
	free(subj);
	free(issuer);

	// check provided certificate chain in built-in cert
	osi.cert_is_valid_self = false;
	X509_STORE *store_pem = X509_STORE_new();
	if (store_pem)
	{
		X509 *crt = NULL;
		while ((crt = PEM_read_bio_X509(pBio, NULL, NULL, NULL)))
		{
			if (!X509_STORE_add_cert(store_pem, crt))
				cs_log("Error: X509_STORE_add_cert() failed");
			X509_free(crt);
		}

		X509_STORE_CTX *ctx_store_pem = X509_STORE_CTX_new();
		if (ctx_store_pem)
		{
			if (X509_STORE_CTX_init(ctx_store_pem, store_pem, pCert, NULL))
			{
				ret = X509_verify_cert(ctx_store_pem);
				if (ret >= 0)
					osi.cert_is_valid_self = ret;
			}
			X509_STORE_CTX_free(ctx_store_pem);
		}
		X509_STORE_free(store_pem);
	}

	// check system ca-certificates.crt
	osi.cert_is_valid_system = false;
	osi.system_ca_file = NULL;
	if (!osi.cert_is_valid_self)
	{
		X509_STORE *store_system = X509_STORE_new();
		if (store_system)
		{
			const char *ca_path;
			snprintf(system_ca_file, sizeof(system_ca_file), "%s/%s", CA_SYSTEM_LOCATION, CA_FILE_NAME);
			if (!file_exists(system_ca_file))
			{
				if (!(ca_path = getenv(X509_get_default_cert_dir_env())))
					ca_path = X509_get_default_cert_dir();
				snprintf(system_ca_file, sizeof(system_ca_file), "%s/%s", ca_path, CA_FILE_NAME);
			}

			if (cs_malloc(&osi.system_ca_file, cs_strlen(system_ca_file) + 1))
				cs_strncpy(osi.system_ca_file, system_ca_file, cs_strlen(system_ca_file) + 1);

			if (X509_STORE_load_locations(store_system, system_ca_file, NULL))
			{
				X509_STORE_CTX *ctx_store_system = X509_STORE_CTX_new();
				if (ctx_store_system)
				{
					if (X509_STORE_CTX_init(ctx_store_system, store_system, pCert, NULL))
					{
						ret = X509_verify_cert(ctx_store_system);
						if (ret >= 0)
							osi.cert_is_valid_system = ret;
					}
					X509_STORE_CTX_free(ctx_store_system);
				}
			}
			else
			{
				cs_log("Error: X509_STORE_load_locations() failed. Unable to load CA certs from %s", system_ca_file);
			}
			X509_STORE_free(store_system);
		}
	}

	// extract public key
	pKey = X509_get_pubkey(pCert);
	osi.pkey_type = NULL;
	if (pKey)
	{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L  // changed in OpenSSL 1.1.0+
		switch (EVP_PKEY_id(pKey))
#else
		switch (EVP_PKEY_type(pKey->type))
#endif
		{
			case EVP_PKEY_RSA:
				snprintf(ptype, sizeof(ptype), "%d bit RSA Key", EVP_PKEY_bits(pKey));
				break;
			case EVP_PKEY_DSA:
				snprintf(ptype, sizeof(ptype), "%d bit DSA Key", EVP_PKEY_bits(pKey));
				break;
			case EVP_PKEY_EC:
				snprintf(ptype, sizeof(ptype), "%d bit ECDSA Key", EVP_PKEY_bits(pKey));
				break;
			default:
				snprintf(ptype, sizeof(ptype), "%d bit non-RSA/DSA Key", EVP_PKEY_bits(pKey));
				break;
		}
		if (cs_malloc(&osi.pkey_type, cs_strlen(ptype) + 1))
			cs_strncpy(osi.pkey_type, ptype, cs_strlen(ptype) + 1);
	}
	else
	{
		cs_log("Error: X509_get_pubkey() failed");
	}

	BIO_free(pBio);
	X509_free(pCert);
	return pKey;
}


static DIGEST hashBinary(const char *binfile, DIGEST *sign)
{
	DIGEST arRetval = {NULL, 0};
	struct stat *fi;
	unsigned char *signature_enc;
	size_t file_size, offset, end, signature_size;
	file_size = offset = end = signature_size = 0;
	unsigned char *data = NULL, *signature_start = NULL, *signature_end = NULL, *p = NULL;

	if (cs_malloc(&fi, sizeof(struct stat)))
	{
		if (!stat(binfile, fi))
		{
			file_size = fi->st_size;
			free(fi);
			// Read binary into memory
			int fd = open(binfile, O_RDONLY);
			data = mmap(0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
			end = file_size;

			// Determine occurrence of last signature marker
			p = data;
			while ((p = memmem(p, (file_size - offset), OBSM, cs_strlen(OBSM))))
			{
				offset = p - data;
				p = p + cs_strlen(OBSM);
				signature_start = p;
			}

			// Determine occurrence of next upx marker
			p = memmem(signature_start, (file_size - offset), UPXM, cs_strlen(UPXM));
			if (p != NULL)
			{
				end = p - data;
			}
			signature_end = p;

			// Get encrypted signature
			if (offset > 0)
			{
				signature_size = end - offset - cs_strlen(OBSM);
				if (cs_malloc(&signature_enc, signature_size))
				{
					memcpy(signature_enc, signature_start, signature_size);
					sign->data = signature_enc;
					sign->size = signature_size;
				}
			}
			else
			{
				offset = file_size;
			}

			// SHA256 hash of binary content without encrypted signature part
			mbedtls_sha256_context ctx;
			mbedtls_sha256_init(&ctx);
			mbedtls_sha256_starts(&ctx, 0);
			mbedtls_sha256_update(&ctx, data, offset); //first chunk from beginning to signature start
			mbedtls_sha256_update(&ctx, signature_end, (file_size - end)); //second chunk from signature end to end of file
			munmap(data, file_size);
			close(fd);

			// Return calculated digest
			arRetval.data = (unsigned char *)OPENSSL_malloc(SHA256_DIGEST_LENGTH);
			arRetval.size = SHA256_DIGEST_LENGTH;
			mbedtls_sha256_finish(&ctx, arRetval.data);
			mbedtls_sha256_free(&ctx);
		}
	}

	return arRetval;
}

static bool verifyBin(const char *binfile, EVP_PKEY *pubkey)
{
	int bResult = 0;
	osi.is_verified = false;
	osi.sign_digest_size = 0;
	osi.hash_digest_size = 0;
	osi.hash_size = 0;
	osi.hash_sha256 = NULL;
	EVP_MD_CTX *mctx = NULL;
	DIGEST sign = {NULL, 0};

	// Get binfile hash digest and encrypted signature
	DIGEST hash = hashBinary(binfile, &sign);
	osi.sign_digest_size = sign.size;

	if (hash.data)
	{
		char shaVal[2 * hash.size + 1];
		hex_encode(hash.data, shaVal, hash.size);

		osi.hash_digest_size = hash.size;
		osi.hash_size = cs_strlen(shaVal);

		if (cs_malloc(&osi.hash_sha256, osi.hash_size + 1))
		{
			cs_strncpy(osi.hash_sha256, strtolower(shaVal), osi.hash_size + 1);
		}
		OPENSSL_free(hash.data);

		if (pubkey && sign.data)
		{
			// Create message digest context
#if OPENSSL_VERSION_NUMBER >= 0x10100000L  // changed in OpenSSL 1.1.0+
			mctx = EVP_MD_CTX_new();
#else
			mctx = EVP_MD_CTX_create();
#endif
			if (!mctx)
			{
				cs_log("Error: EVP_MD_CTX allocation failed");
			}
			else
			{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L  // changed in OpenSSL 1.1.0+
				EVP_PKEY_CTX *pkctx = NULL;
				if (EVP_DigestVerifyInit(mctx, &pkctx, EVP_sha256(), NULL, pubkey) <= 0)
				{
					cs_log("Error: EVP_DigestVerifyInit() failed");
				}
				else if (EVP_DigestVerifyUpdate(mctx, shaVal, cs_strlen(shaVal)) <= 0)
				{
					cs_log("Error: EVP_DigestVerifyUpdate() failed");
				}
				else
				{
					bResult = (EVP_DigestVerifyFinal(mctx, sign.data, sign.size) == 1);
					osi.is_verified = (bResult == 1);
				}
#else
				if (!EVP_VerifyInit(mctx, EVP_sha256()))
				{
					cs_log("Error: EVP_VerifyInit() failed");
				}
				else if (!EVP_VerifyUpdate(mctx, shaVal, cs_strlen(shaVal)))
				{
					cs_log("Error: EVP_VerifyUpdate() failed");
				}
				else
				{
					bResult = EVP_VerifyFinal(mctx, sign.data, sign.size, pubkey);
					osi.is_verified = (bResult == 1);
				}
#endif
			}
		}
	}

	if (sign.data) free(sign.data);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L  // changed in OpenSSL 1.1.0+
	EVP_MD_CTX_free(mctx);
#else
	EVP_MD_CTX_destroy(mctx);
#endif
	return (bResult == 1);
}

bool init_signing_info(const char *binfile)
{
	EVP_PKEY *pubkey = NULL;
	memset(&osi, 0, sizeof(struct o_sign_info));

	// verify signing certificate and extract public key
	pubkey = verify_cert();

	// resolve binfile in PATH
	char *tmp = find_in_path(binfile);
	osi.binfile_exists = (tmp != NULL);
	snprintf(osi.resolved_binfile, sizeof(osi.resolved_binfile), "%s", tmp ? tmp : binfile);

	cs_log ("Binary         = %s file %s%s",
			(osi.binfile_exists ? "Verifying" : "Unable to access"),
			osi.resolved_binfile,
			(osi.binfile_exists ? "..." : "!"));

	// verify binfile using public key
	bool ret = verifyBin(osi.resolved_binfile, pubkey);

	cs_log ("Signature      = %s", (ret ? "Valid - Binary's signature was successfully verified using the built-in Public Key"
										: "Error: Binary's signature is invalid! Shutting down..."));

	if (pubkey)
	{
		cs_log("Certificate    = %s %s Certificate, %s %s",
				((osi.cert_is_valid_self || osi.cert_is_valid_system) ? "Trusted" : "Untrusted"),
				(osi.cert_is_cacert ? "CA" : "Self Signed"),
				(osi.cert_is_expired ? "expired since" : "valid until"),
				osi.cert_valid_to);
	}
	else
	{
		cs_log("Certificate    = Error: Built-in Public Key could not be extracted!");
	}

	if (tmp) free(tmp);
	EVP_PKEY_free(pubkey);

	return ret;
}
