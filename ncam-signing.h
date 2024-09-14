#ifndef Ncam_SIGNING_H_
#define Ncam_SIGNING_H_

#ifdef WITH_SSL
#include <openssl/x509.h>
#include <openssl/pem.h>
#endif

#define OBSM "!OBSM!" //Ncam Binary Signature Marker
#define CA_FILE_NAME "ca-certificates.crt" //System Certificate Trust Store Filename
#define CA_SYSTEM_LOCATION "/etc/ssl/certs" //System Certificate Trust Store Location

typedef struct {
	unsigned char *data;
	size_t size;
} DIGEST;

struct o_sign_info
{
	bool	is_verified;
	int		cert_version;
	char	cert_valid_from[40];
	char	cert_valid_to[40];
	bool	cert_is_expired;
	char	*cert_serial;
	char	*cert_fingerprint;
	char	*cert_subject;
	char	*cert_issuer;
	bool	cert_is_cacert;
	bool	cert_is_valid_self;
	bool	cert_is_valid_system;
	char	*system_ca_file;
	char	*pkey_type;
	int		sign_digest_size;
	int		hash_digest_size;
	int		hash_size;
	char	*hash_sha1;
};

extern struct o_sign_info osi;
bool init_signing_info(const char *binfile);
EVP_PKEY *verify_cert(void);
DIGEST hashBinary(const char *binfile, DIGEST *sign);
int verifyBin(const char *binfile, EVP_PKEY *pubkey);
char* _X509_NAME_oneline_utf8(X509_NAME *name);
void hex_encode(unsigned char* readbuf, void *writebuf, size_t len);
void convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len);
time_t ASN1_TIME_to_posix_time(const ASN1_TIME* time);
time_t posix_time(unsigned int year, unsigned int month, unsigned int day, unsigned int hour, unsigned int min, unsigned int sec);

#endif
