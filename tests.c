/*
 * NCam self tests
 * This file contains tests for different config parsers and generators
 * Build this file using `make tests`
 */
#include "globals.h"

#include "ncam-array.h"
#include "ncam-string.h"
#include "ncam-conf-chk.h"
#include "ncam-conf-mk.h"
#include "cscrypt/md5.h"
#include "cscrypt/sha1.h"
#include "cscrypt/sha256.h"
#include "cscrypt/mdc2.h"
#include "cscrypt/aes.h"
#include "cscrypt/fast_aes.h"
#include "cscrypt/des.h"
#include "cscrypt/idea.h"
#include "cscrypt/rc6.h"
#include "cscrypt/bn.h"
#include "ncam-aes.h"

struct test_vec
{
	const char *in;  // Input data
	const char *out; // Expected output data (if out is NULL, then assume in == out)
};

typedef void  (CHK_FN)  (char *, void *);
typedef char *(MK_T_FN) (void *);
typedef void  (CLEAR_FN)(void *);
typedef bool  (CLONE_FN)(void *, void *);
typedef bool  (HAS_DATA_FN)(void *);

struct test_type
{
	char     *desc;         // Test textual description
	void     *data;         // Pointer to basic data structure
	void     *data_c;       // Pointer to data structure that will hold cloned data (for clone_ tests)
	size_t   data_sz;       // Data structure size
	CHK_FN   *chk_fn;       // chk_XXX() func for the data type
	MK_T_FN  *mk_t_fn;      // mk_t_XXX() func for the data type
	CLEAR_FN *clear_fn;     // clear_XXX() func for the data type
	CLONE_FN *clone_fn;     // clone_XXX() func for the data type
	HAS_DATA_FN *has_data_fn; // Reports whether parsed data contains cloneable entries
	const struct test_vec *test_vec; // Array of test vectors
};

#define DEFINE_TEST_ADAPTERS(NAME, TYPE, NUM_FIELD) \
	static void chk_##NAME##_adapter(char *value, void *data) \
	{ \
		chk_##NAME(value, (TYPE *)data); \
	} \
	\
	static char *mk_t_##NAME##_adapter(void *data) \
	{ \
		return mk_t_##NAME((TYPE *)data); \
	} \
	\
	static void clear_##NAME##_adapter(void *data) \
	{ \
		NAME##_clear((TYPE *)data); \
	} \
	\
	static bool clone_##NAME##_adapter(void *src, void *dst) \
	{ \
		return NAME##_clone((TYPE *)src, (TYPE *)dst); \
	} \
	\
	static bool has_data_##NAME##_adapter(void *data) \
	{ \
		return ((TYPE *)data)->NUM_FIELD > 0; \
	}

DEFINE_TEST_ADAPTERS(ecm_whitelist, ECM_WHITELIST, ewnum);
DEFINE_TEST_ADAPTERS(ecm_hdr_whitelist, ECM_HDR_WHITELIST, ehnum);
DEFINE_TEST_ADAPTERS(tuntab, TUNTAB, ttnum);
DEFINE_TEST_ADAPTERS(ftab, FTAB, nfilts);
DEFINE_TEST_ADAPTERS(caidvaluetab, CAIDVALUETAB, cvnum);
DEFINE_TEST_ADAPTERS(caidtab, CAIDTAB, ctnum);

#undef DEFINE_TEST_ADAPTERS

static int run_parser_test(struct test_type *t)
{
	int failures = 0;

	memset(t->data, 0, t->data_sz);
	memset(t->data_c, 0, t->data_sz);
	printf("%s\n", t->desc);
	const struct test_vec *vec = t->test_vec;
	while (vec->in)
	{
		bool ok, clone_ok, clone_required, clone_failed;
		bool failed_case;
		char *generated;
		printf(" Testing \"%s\"", vec->in);
		char *input_setting = cs_strdup(vec->in);
		t->chk_fn(input_setting, t->data);
		clone_required = t->has_data_fn(t->data);
		clone_ok = t->clone_fn(t->data, t->data_c);
		clone_failed = clone_required && !clone_ok;
		if (clone_ok)
		{
			t->clear_fn(t->data); // Check if 'clear' works
			generated = t->mk_t_fn(t->data_c); // Use cloned data
		}
		else
		{
			generated = t->mk_t_fn(t->data);
			t->clear_fn(t->data); // Check if 'clear' works
		}
		if (vec->out)
			ok = strcmp(vec->out, generated) == 0;
		else
			ok = strcmp(vec->in, generated) == 0;
		failed_case = clone_failed || !ok;
		if (!failed_case)
		{
			printf(" [OK]\n");
		} else {
			printf("\n");
			if (clone_failed)
			{
				printf(" === CLONE ERROR ===\n");
				printf("  Input data:   \"%s\"\n", vec->in);
				printf("  Clone result: failed\n");
				printf("\n");
				failures++;
			}
			if (!ok)
			{
				printf(" === ERROR ===\n");
				printf("  Input data:   \"%s\"\n", vec->in);
				printf("  Got result:   \"%s\"\n", generated);
				printf("  Expected out: \"%s\"\n", vec->out ? vec->out : vec->in);
				printf("\n");
				failures++;
			}
		}
		free_mk_t(generated);
		free(input_setting);
		fflush(stdout);
		vec++;
	}
	t->clear_fn(t->data_c);
	return failures;
}

/* --------------------------------------------------------------------- */
/*  Crypto test helpers                                             */
/* --------------------------------------------------------------------- */

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decode hex string into buf. Returns number of decoded bytes, -1 on error. */
static int hex_decode(const char *hex, uint8_t *buf, size_t buf_sz)
{
	size_t n = 0;
	while (*hex)
	{
		int hi = hex_nibble(*hex++);
		if (hi < 0) return -1;
		int lo = hex_nibble(*hex++);
		if (lo < 0) return -1;
		if (n >= buf_sz) return -1;
		buf[n++] = (uint8_t)((hi << 4) | lo);
	}
	return (int)n;
}

/* Encode binary buf to lowercase hex. `out` must hold 2*len+1 bytes. */
static void hex_encode(const uint8_t *buf, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	for (size_t i = 0; i < len; i++)
	{
		out[i * 2 + 0] = digits[(buf[i] >> 4) & 0xF];
		out[i * 2 + 1] = digits[(buf[i] >> 0) & 0xF];
	}
	out[len * 2] = '\0';
}

static bool hex_equal(const uint8_t *bin, size_t bin_len, const char *hex)
{
	char enc[2 * 256 + 1];
	if (bin_len > 256) return false;
	hex_encode(bin, bin_len, enc);
	return strcasecmp(enc, hex) == 0;
}

static void report_mismatch(const char *suite, const char *name,
							const uint8_t *got, size_t got_len,
							const char *expected_hex)
{
	char gothex[2 * 256 + 1];
	if (got_len > 256) got_len = 256;
	hex_encode(got, got_len, gothex);
	printf("\n === ERROR ===\n");
	printf("  Suite:        %s\n", suite);
	printf("  Case:         %s\n", name);
	printf("  Got:          %s\n", gothex);
	printf("  Expected:     %s\n\n", expected_hex);
}

/* --------------------------------------------------------------------- */
/*  Hash test harness                                                    */
/* --------------------------------------------------------------------- */

struct hash_vec
{
	const char *name;
	const char *input;      /* NUL-terminated text input */
	size_t      input_rep;  /* repeat input this many times (0 or 1 = single) */
	const char *expected;   /* hex-encoded expected digest */
};

/* MD5: uses the one-shot MD5() helper.
 *      RFC 1321 Appendix A.5 test suite. */
static int run_md5_tests(void)
{
	static const struct hash_vec vec[] = {
		{ "empty",      "",                                                         0, "d41d8cd98f00b204e9800998ecf8427e" },
		{ "a",          "a",                                                        0, "0cc175b9c0f1b6a831c399e269772661" },
		{ "abc",        "abc",                                                      0, "900150983cd24fb0d6963f7d28e17f72" },
		{ "msgdigest",  "message digest",                                           0, "f96b697d7cb7938d525a2f31aaf161d0" },
		{ "alphabet",   "abcdefghijklmnopqrstuvwxyz",                               0, "c3fcd3d76192e4007dfb496cca67e13b" },
		{ "alphanum62", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0, "d174ab98d277d9f5a5611c2c9f419d9f" },
		{ "8x10digits", "1234567890",                                               8, "57edf4a22be3c955ac49da2e2107b67a" },
		{ NULL, NULL, 0, NULL }
	};
	int failures = 0;
	printf("MD5 test vectors\n");
	for (const struct hash_vec *v = vec; v->name; v++)
	{
		/* Materialize (possibly repeated) input as a flat buffer */
		size_t il = strlen(v->input);
		size_t rep = v->input_rep ? v->input_rep : 1;
		size_t total = il * rep;
		uint8_t *in = calloc(1, total + 1);
		for (size_t i = 0; i < rep; i++) memcpy(in + i * il, v->input, il);

		uint8_t md[16];
		MD5(in, total, md);
		free(in);

		printf(" Testing \"%s\"", v->name);
		if (hex_equal(md, 16, v->expected)) { printf(" [OK]\n"); }
		else { report_mismatch("MD5", v->name, md, 16, v->expected); failures++; }
		fflush(stdout);
	}
	return failures;
}

/* SHA1: exercises whole-input and streaming Init/Update/Final calls,
 *       split on byte 1 to catch partial-update bugs.
 *       Vectors: FIPS 180-1. */
static int run_sha1_tests(void)
{
	static const struct hash_vec vec[] = {
		{ "empty",   "",                                        0, "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
		{ "abc",     "abc",                                     0, "a9993e364706816aba3e25717850c26c9cd0d89d" },
		{ "448bit",  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		                                                        0, "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
		{ "fox",     "The quick brown fox jumps over the lazy dog", 0, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" },
		{ "1M_a",    "a",                                   1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
		{ NULL, NULL, 0, NULL }
	};
	int failures = 0;
	printf("SHA1 test vectors\n");
	for (const struct hash_vec *v = vec; v->name; v++)
	{
		size_t il = strlen(v->input);
		size_t rep = v->input_rep ? v->input_rep : 1;
		size_t total = il * rep;
		uint8_t *in = calloc(1, total + 1);
		for (size_t i = 0; i < rep; i++) memcpy(in + i * il, v->input, il);

		uint8_t md1[20], md2[20];

		/* one-shot via full-buffer Update (master has no SHA1() helper) */
		{ SHA_CTX c0; SHA1_Init(&c0); if (total) SHA1_Update(&c0, in, total); SHA1_Final(md1, &c0); }

		/* streaming: one byte, then the rest */
		SHA_CTX c;
		SHA1_Init(&c);
		if (total > 0)
		{
			SHA1_Update(&c, in, 1);
			if (total > 1) SHA1_Update(&c, in + 1, total - 1);
		}
		SHA1_Final(md2, &c);

		free(in);

		printf(" Testing \"%s\" oneshot", v->name);
		if (hex_equal(md1, 20, v->expected)) { printf(" [OK]"); }
		else { report_mismatch("SHA1 oneshot", v->name, md1, 20, v->expected); failures++; }

		printf(" / streaming");
		if (hex_equal(md2, 20, v->expected)) { printf(" [OK]\n"); }
		else { report_mismatch("SHA1 streaming", v->name, md2, 20, v->expected); failures++; }
		fflush(stdout);
	}
	return failures;
}

static int run_sha1_input_tests(void)
{
	static const size_t sizes[] = { 0, 1, 55, 56, 57, 63, 64, 65, 127, 128, 129, 255 };
	static const size_t chunks[] = { 1, 7, 63, 64, 65, 255 };
	union { uint32_t align; uint8_t bytes[259]; } input;
	uint8_t saved[sizeof(input.bytes)], expected[20], got[20];
	int failures = 0;
	for (size_t i = 0; i < sizeof(saved); i++) saved[i] = (uint8_t)(i * 37 + 11);
	printf("SHA1 input preservation and update boundaries");
	for (size_t offset = 1; offset <= 3; offset++)
	{
		for (size_t n = 0; n < sizeof(sizes) / sizeof(sizes[0]); n++)
		{
			SHA_CTX reference;
			SHA1_Init(&reference);
			for (size_t i = 0; i < sizes[n]; i++) SHA1_Update(&reference, saved + offset + i, 1);
			SHA1_Final(expected, &reference);
			for (size_t c = 0; c < sizeof(chunks) / sizeof(chunks[0]); c++)
			{
				for (size_t prefix = 0; prefix <= 1 && prefix <= sizes[n]; prefix++)
				{
					SHA_CTX context;
					memcpy(input.bytes, saved, sizeof(saved));
					SHA1_Init(&context);
					if (prefix) SHA1_Update(&context, input.bytes + offset, prefix);
					for (size_t pos = prefix; pos < sizes[n]; )
					{
						size_t count = sizes[n] - pos;
						if (count > chunks[c]) count = chunks[c];
						SHA1_Update(&context, input.bytes + offset + pos, count);
						pos += count;
					}
					SHA1_Final(got, &context);
					if (memcmp(expected, got, sizeof(got)) || memcmp(input.bytes, saved, sizeof(saved)))
					{
						printf("\n === ERROR === offset=%zu size=%zu chunk=%zu prefix=%zu\n", offset, sizes[n], chunks[c], prefix);
						failures++;
					}
				}
			}
		}
	}
	if (!failures) printf(" [OK]\n");

	/* Const storage also catches writes on hosts that map it read-only. */
	static const uint8_t readonly[] =
		"0123456789abcdef0123456789abcdef0123456789abcdef"
		"0123456789abcdef0123456789abcdef0123456789abcdef"
		"0123456789abcdef0123456789abcdef0123456789abcdef";
	SHA_CTX context, reference;
	SHA1_Init(&reference);
	for (size_t i = 0; i < 128; i++) SHA1_Update(&reference, readonly + 1 + i, 1);
	SHA1_Final(expected, &reference);
	SHA1_Init(&context);
	SHA1_Update(&context, readonly + 1, 128);
	SHA1_Final(got, &context);
	printf("SHA1 const input");
	if (!memcmp(expected, got, sizeof(got))) printf(" [OK]\n");
	else { printf(" [FAIL]\n"); failures++; }
#if !defined(WITH_SSL) && !defined(WITH_LIBCRYPTO)
	/* The bundled transform takes state words; OpenSSL takes a context. */
	SHA1_Init(&reference);
	SHA1_Update(&reference, readonly + 1, 64);
	SHA1_Init(&context);
	SHA1_Transform(context.state, readonly + 1);
	printf("SHA1 direct transform of const unaligned input");
	if (!memcmp(reference.state, context.state, sizeof(context.state))) printf(" [OK]\n");
	else { printf(" [FAIL]\n"); failures++; }
#endif
	fflush(stdout);
	return failures;
}

/* SHA256: streaming API only.
 *         Vectors: NIST FIPS 180-2. */
static int run_sha256_tests(void)
{
	static const struct hash_vec vec[] = {
		{ "empty",   "",                                        0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
		{ "abc",     "abc",                                     0, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
		{ "448bit",  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		                                                        0, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
		{ "1M_a",    "a",                                   1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" },
		{ NULL, NULL, 0, NULL }
	};
	int failures = 0;
	printf("SHA256 test vectors\n");
	for (const struct hash_vec *v = vec; v->name; v++)
	{
		size_t il = strlen(v->input);
		size_t rep = v->input_rep ? v->input_rep : 1;
		size_t total = il * rep;
		uint8_t *in = calloc(1, total + 1);
		for (size_t i = 0; i < rep; i++) memcpy(in + i * il, v->input, il);

		uint8_t md[32];
		mbedtls_sha256_context c;
		mbedtls_sha256_init(&c);
		mbedtls_sha256_starts(&c, 0);
		/* feed in 2 chunks to also exercise streaming */
		if (total > 1)
		{
			mbedtls_sha256_update(&c, in, total / 2);
			mbedtls_sha256_update(&c, in + total / 2, total - total / 2);
		}
		else if (total == 1)
		{
			mbedtls_sha256_update(&c, in, 1);
		}
		mbedtls_sha256_finish(&c, md);
		mbedtls_sha256_free(&c);
		free(in);

		printf(" Testing \"%s\"", v->name);
		if (hex_equal(md, 32, v->expected)) { printf(" [OK]\n"); }
		else { report_mismatch("SHA256", v->name, md, 32, v->expected); failures++; }
		fflush(stdout);
	}
	return failures;
}

/* --------------------------------------------------------------------- */
/*  AES                                                                  */
/* --------------------------------------------------------------------- */

/* Vectors: NIST SP 800-38A F.1.1/F.1.5 (ECB) and F.2.1/F.2.5 (CBC). */

struct aes_vec
{
	const char *name;
	const char *key_hex;    /* 16, 24 or 32 bytes */
	const char *iv_hex;     /* NULL for ECB */
	const char *pt_hex;     /* plaintext, multiple of 16 */
	const char *ct_hex;     /* expected ciphertext */
};

static int aes_key_bits_from_hex(const char *hex)
{
	size_t n = strlen(hex) / 2;
	if (n == 16) return 128;
	if (n == 24) return 192;
	if (n == 32) return 256;
	return -1;
}

/* AES ECB via AES_set_encrypt_key + AES_encrypt (block-at-a-time),
 * and the inverse via AES_set_decrypt_key + AES_decrypt. */
static int run_aes_ecb_tests(void)
{
	static const struct aes_vec vec[] = {
		{ "AES128-ECB NIST blk1",
		  "2b7e151628aed2a6abf7158809cf4f3c", NULL,
		  "6bc1bee22e409f96e93d7e117393172a",
		  "3ad77bb40d7a3660a89ecaf32466ef97" },
		{ "AES128-ECB NIST blk2",
		  "2b7e151628aed2a6abf7158809cf4f3c", NULL,
		  "ae2d8a571e03ac9c9eb76fac45af8e51",
		  "f5d3d58503b9699de785895a96fdbaaf" },
		{ "AES192-ECB NIST F.1.3",
		  "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", NULL,
		  "6bc1bee22e409f96e93d7e117393172a",
		  "bd334f1d6e45f25ff712a214571fa5cc" },
		{ "AES256-ECB NIST blk1",
		  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", NULL,
		  "6bc1bee22e409f96e93d7e117393172a",
		  "f3eed1bdb5d2a03c064b5a7e3db181f8" },
		{ NULL, NULL, NULL, NULL, NULL }
	};
	int failures = 0;
	printf("AES ECB test vectors (AES_encrypt / AES_decrypt)\n");
	for (const struct aes_vec *v = vec; v->name; v++)
	{
		int bits = aes_key_bits_from_hex(v->key_hex);
		uint8_t key[32], pt[16], expct[16], got[16];
		hex_decode(v->key_hex, key, sizeof(key));
		hex_decode(v->pt_hex, pt, sizeof(pt));
		hex_decode(v->ct_hex, expct, sizeof(expct));

		/* Encrypt */
		AES_KEY ekey;
		AES_set_encrypt_key(key, bits, &ekey);
		AES_encrypt(pt, got, &ekey);
		printf(" Testing \"%s\" encrypt", v->name);
		if (memcmp(got, expct, 16) == 0) { printf(" [OK]"); }
		else { report_mismatch("AES-ECB encrypt", v->name, got, 16, v->ct_hex); failures++; }

		/* Decrypt */
		AES_KEY dkey;
		AES_set_decrypt_key(key, bits, &dkey);
		AES_decrypt(expct, got, &dkey);
		printf(" / decrypt");
		if (memcmp(got, pt, 16) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("AES-ECB decrypt", v->name, got, 16, v->pt_hex); failures++; }
		fflush(stdout);
	}
	return failures;
}

/* AES CBC via AES_cbc_encrypt (OpenSSL-compat surface). Ensures
 * IV chaining is correct across concatenated blocks in a single call
 * AND across multiple calls with the caller-preserved ivec. */
static int run_aes_cbc_tests(void)
{
	static const struct aes_vec vec[] = {
		{ "AES128-CBC NIST F.2.1",
		  "2b7e151628aed2a6abf7158809cf4f3c",
		  "000102030405060708090a0b0c0d0e0f",
		  "6bc1bee22e409f96e93d7e117393172a"
		  "ae2d8a571e03ac9c9eb76fac45af8e51"
		  "30c81c46a35ce411e5fbc1191a0a52ef"
		  "f69f2445df4f9b17ad2b417be66c3710",
		  "7649abac8119b246cee98e9b12e9197d"
		  "5086cb9b507219ee95db113a917678b2"
		  "73bed6b8e3c1743b7116e69e22229516"
		  "3ff1caa1681fac09120eca307586e1a7" },
		{ "AES256-CBC NIST F.2.5",
		  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		  "000102030405060708090a0b0c0d0e0f",
		  "6bc1bee22e409f96e93d7e117393172a",
		  "f58c4c04d6e5f1ba779eabfb5f7bfbd6" },
		{ NULL, NULL, NULL, NULL, NULL }
	};
	int failures = 0;
	printf("AES CBC test vectors (AES_cbc_encrypt)\n");
	for (const struct aes_vec *v = vec; v->name; v++)
	{
		int bits = aes_key_bits_from_hex(v->key_hex);
		size_t len = strlen(v->pt_hex) / 2;
		uint8_t key[32], iv[16], pt[64], expct[64], got[64];
		hex_decode(v->key_hex, key, sizeof(key));
		hex_decode(v->iv_hex, iv, sizeof(iv));
		hex_decode(v->pt_hex, pt, sizeof(pt));
		hex_decode(v->ct_hex, expct, sizeof(expct));

		/* --- Encrypt: single call --- */
		{
			uint8_t iv_local[16];
			memcpy(iv_local, iv, 16);
			AES_KEY ekey;
			AES_set_encrypt_key(key, bits, &ekey);
			AES_cbc_encrypt(pt, got, len, &ekey, iv_local, AES_ENCRYPT);
			printf(" Testing \"%s\" enc-single", v->name);
			if (memcmp(got, expct, len) == 0) { printf(" [OK]"); }
			else { report_mismatch("AES-CBC enc-single", v->name, got, len, v->ct_hex); failures++; }
		}

		/* --- Encrypt: block-by-block via preserved ivec (IV chaining) --- */
		if (len >= 32)
		{
			uint8_t iv_local[16];
			memcpy(iv_local, iv, 16);
			AES_KEY ekey;
			AES_set_encrypt_key(key, bits, &ekey);
			memset(got, 0, sizeof(got));
			for (size_t off = 0; off < len; off += 16)
				AES_cbc_encrypt(pt + off, got + off, 16, &ekey, iv_local, AES_ENCRYPT);
			printf(" / enc-chunked");
			if (memcmp(got, expct, len) == 0) { printf(" [OK]"); }
			else { report_mismatch("AES-CBC enc-chunked", v->name, got, len, v->ct_hex); failures++; }
		}

		/* --- Decrypt: single call --- */
		{
			uint8_t iv_local[16];
			memcpy(iv_local, iv, 16);
			AES_KEY dkey;
			AES_set_decrypt_key(key, bits, &dkey);
			AES_cbc_encrypt(expct, got, len, &dkey, iv_local, AES_DECRYPT);
			printf(" / dec-single");
			if (memcmp(got, pt, len) == 0) { printf(" [OK]\n"); }
			else { report_mismatch("AES-CBC dec-single", v->name, got, len, v->pt_hex); failures++; }
		}
		fflush(stdout);
	}
	return failures;
}

/* Exercise the ncam-style AesCtx API for both ECB and CBC modes. */
static int run_aesctx_tests(void)
{
	/* Reuse NIST vectors. */
	static const struct aes_vec ecb_vec =
	{ "AES128-ECB NIST blk1 (AesCtx)",
	  "2b7e151628aed2a6abf7158809cf4f3c", NULL,
	  "6bc1bee22e409f96e93d7e117393172a",
	  "3ad77bb40d7a3660a89ecaf32466ef97" };
	static const struct aes_vec cbc_vec =
	{ "AES128-CBC NIST F.2.1 (AesCtx)",
	  "2b7e151628aed2a6abf7158809cf4f3c",
	  "000102030405060708090a0b0c0d0e0f",
	  "6bc1bee22e409f96e93d7e117393172a"
	  "ae2d8a571e03ac9c9eb76fac45af8e51",
	  "7649abac8119b246cee98e9b12e9197d"
	  "5086cb9b507219ee95db113a917678b2" };

	int failures = 0;
	printf("AesCtxIni / AesEncrypt / AesDecrypt\n");

	{
		uint8_t key[16], pt[16], expct[16], got[16];
		hex_decode(ecb_vec.key_hex, key, sizeof(key));
		hex_decode(ecb_vec.pt_hex, pt, sizeof(pt));
		hex_decode(ecb_vec.ct_hex, expct, sizeof(expct));
		AesCtx c;
		AesCtxIni(&c, NULL, key, KEY128, EBC);
		AesEncrypt(&c, pt, got, 16);
		printf(" Testing \"%s\" encrypt", ecb_vec.name);
		if (memcmp(got, expct, 16) == 0) { printf(" [OK]"); }
		else { report_mismatch("AesCtx-ECB enc", ecb_vec.name, got, 16, ecb_vec.ct_hex); failures++; }

		AesCtxIni(&c, NULL, key, KEY128, EBC);
		AesDecrypt(&c, expct, got, 16);
		printf(" / decrypt");
		if (memcmp(got, pt, 16) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("AesCtx-ECB dec", ecb_vec.name, got, 16, ecb_vec.pt_hex); failures++; }
	}

	{
		uint8_t key[16], iv[16], pt[32], expct[32], got[32];
		hex_decode(cbc_vec.key_hex, key, sizeof(key));
		hex_decode(cbc_vec.iv_hex, iv, sizeof(iv));
		hex_decode(cbc_vec.pt_hex, pt, sizeof(pt));
		hex_decode(cbc_vec.ct_hex, expct, sizeof(expct));
		AesCtx c;
		AesCtxIni(&c, iv, key, KEY128, CBC);
		AesEncrypt(&c, pt, got, 32);
		printf(" Testing \"%s\" encrypt", cbc_vec.name);
		if (memcmp(got, expct, 32) == 0) { printf(" [OK]"); }
		else { report_mismatch("AesCtx-CBC enc", cbc_vec.name, got, 32, cbc_vec.ct_hex); failures++; }

		AesCtxIni(&c, iv, key, KEY128, CBC);
		AesDecrypt(&c, expct, got, 32);
		printf(" / decrypt");
		if (memcmp(got, pt, 32) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("AesCtx-CBC dec", cbc_vec.name, got, 32, cbc_vec.pt_hex); failures++; }
	}
	fflush(stdout);
	return failures;
}

/* --------------------------------------------------------------------- */
/*  DES / 3DES                                                           */
/* --------------------------------------------------------------------- */

/* Single-block DES: FIPS 81 variable-plaintext vector.
 * 3DES EDE2 CBC: reversal-symmetry (encrypt then decrypt recovers
 *                plaintext). */
static int run_des_tests(void)
{
	int failures = 0;
	printf("DES / 3DES test vectors\n");

	/* --- DES ECB single block, Stallings/Schneier known vector --- */
	{
		uint8_t key[8];
		uint8_t pt[8];
		uint8_t expct[8];
		uint8_t buf[8];
		hex_decode("133457799bbcdff1", key, sizeof(key));
		hex_decode("0123456789abcdef", pt, sizeof(pt));
		hex_decode("85e813540f0ab405", expct, sizeof(expct));

		memcpy(buf, pt, 8);
		des_ecb_encrypt(buf, key, 8);
		printf(" Testing \"DES-ECB Stallings\" encrypt");
		if (memcmp(buf, expct, 8) == 0) { printf(" [OK]"); }
		else { report_mismatch("DES-ECB enc", "Stallings", buf, 8, "85e813540f0ab405"); failures++; }

		memcpy(buf, expct, 8);
		des_ecb_decrypt(buf, key, 8);
		printf(" / decrypt");
		if (memcmp(buf, pt, 8) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("DES-ECB dec", "Stallings", buf, 8, "0123456789abcdef"); failures++; }
	}

	/* --- DES-CBC known-answer (verified against OpenSSL 3 + legacy provider) --- */
	{
		uint8_t key[8], iv[8], iv_work[8];
		uint8_t pt[16], expct[16], buf[16];
		hex_decode("0123456789abcdef", key, sizeof(key));
		hex_decode("1234567890abcdef", iv, sizeof(iv));
		hex_decode("00000000000000001111111111111111", pt, sizeof(pt));
		hex_decode("bd661569ae874e2564ac6b48fd53b66d", expct, sizeof(expct));

		memcpy(buf, pt, 16);
		memcpy(iv_work, iv, 8);
		des_cbc_encrypt(buf, iv_work, key, 16);
		printf(" Testing \"DES-CBC KAT\" encrypt");
		if (memcmp(buf, expct, 16) == 0) { printf(" [OK]"); }
		else { report_mismatch("DES-CBC enc", "KAT", buf, 16, "bd661569ae874e2564ac6b48fd53b66d"); failures++; }

		memcpy(buf, expct, 16);
		memcpy(iv_work, iv, 8);
		des_cbc_decrypt(buf, iv_work, key, 16);
		printf(" / decrypt");
		if (memcmp(buf, pt, 16) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("DES-CBC dec", "KAT", buf, 16, "00000000000000001111111111111111"); failures++; }
	}

	/* --- 3DES-EDE2-CBC known-answer (verified via openssl des-ede-cbc) --- */
	{
		uint8_t k1[8], k2[8], iv[8], iv_work[8];
		uint8_t pt[16], expct[16], buf[16];
		hex_decode("0123456789abcdef", k1, sizeof(k1));
		hex_decode("fedcba9876543210", k2, sizeof(k2));
		hex_decode("a1b2c3d4e5f6a7b8", iv, sizeof(iv));
		hex_decode("00000000000000001111111111111111", pt, sizeof(pt));
		hex_decode("1da2ecb423be00f72e9fb046777c3ca9", expct, sizeof(expct));

		memcpy(buf, pt, 16);
		memcpy(iv_work, iv, 8);
		des_ede2_cbc_encrypt(buf, iv_work, k1, k2, 16);
		printf(" Testing \"3DES-EDE2-CBC KAT\" encrypt");
		if (memcmp(buf, expct, 16) == 0) { printf(" [OK]"); }
		else { report_mismatch("3DES-EDE2-CBC enc", "KAT", buf, 16, "1da2ecb423be00f72e9fb046777c3ca9"); failures++; }

		memcpy(buf, expct, 16);
		memcpy(iv_work, iv, 8);
		des_ede2_cbc_decrypt(buf, iv_work, k1, k2, 16);
		printf(" / decrypt");
		if (memcmp(buf, pt, 16) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("3DES-EDE2-CBC dec", "KAT", buf, 16, "00000000000000001111111111111111"); failures++; }
	}

	/* --- 3DES-EDE2 ECB single-block reversal (des_ecb3_encrypt/decrypt) --- */
	{
		uint8_t key[16];
		uint8_t pt[8], tmp[8];
		hex_decode("0123456789abcdeffedcba9876543210", key, sizeof(key));
		hex_decode("1111222233334444", pt, sizeof(pt));
		memcpy(tmp, pt, 8);
		des_ecb3_encrypt(tmp, key);
		des_ecb3_decrypt(tmp, key);
		printf(" Testing \"3DES-ECB3 reversal\"");
		if (memcmp(tmp, pt, 8) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("3DES-ECB3 reversal", "rt", tmp, 8, "1111222233334444"); failures++; }
	}

	fflush(stdout);
	return failures;
}

/* --------------------------------------------------------------------- */
/*  Bignum / RSA modular exponentiation                                  */
/* --------------------------------------------------------------------- */

/* Tiny modexp vectors — validates that BN_mod_exp does X = A^E mod N
 * correctly. Use small numbers first, then a realistic RSA size. */
static int run_bn_tests(void)
{
	int failures = 0;
	printf("Bignum BN_mod_exp test vectors\n");

	/* 2^10 mod 1001 = 1024 mod 1001 = 23
	 * Note: N must be odd — mbedtls_mpi_exp_mod uses Montgomery
	 * multiplication which requires an odd modulus. ncam's real RSA
	 * moduli are always odd so this is not a functional limitation. */
	{
		BIGNUM *a = BN_new();
		BIGNUM *e = BN_new();
		BIGNUM *m = BN_new();
		BIGNUM *r = BN_new();
		BN_CTX *ctx = BN_CTX_new();
		BN_set_word(a, 2);
		BN_set_word(e, 10);
		BN_set_word(m, 1001);
		BN_mod_exp(r, a, e, m, ctx);
		unsigned long got = BN_get_word(r);
		printf(" Testing \"2^10 mod 1001\"");
		if (got == 23) { printf(" [OK]\n"); }
		else { printf("\n === ERROR ===\n  Got: %lu  Expected: 23\n\n", got); failures++; }
		BN_free(a); BN_free(e); BN_free(m); BN_free(r); BN_CTX_free(ctx);
	}

	/* Classical Fermat-ish: 5^117 mod 19 == 1 (Fermat says 5^18 mod 19 = 1,
	 * and 117 = 6*18 + 9, so 5^117 = 5^9 mod 19 = 1953125 mod 19.
	 * 1953125 / 19 = 102796.05... 19*102796 = 1953124, so remainder 1.) */
	{
		BIGNUM *a = BN_new();
		BIGNUM *e = BN_new();
		BIGNUM *m = BN_new();
		BIGNUM *r = BN_new();
		BN_CTX *ctx = BN_CTX_new();
		BN_set_word(a, 5);
		BN_set_word(e, 117);
		BN_set_word(m, 19);
		BN_mod_exp(r, a, e, m, ctx);
		unsigned long got = BN_get_word(r);
		printf(" Testing \"5^117 mod 19\"");
		if (got == 1) { printf(" [OK]\n"); }
		else { printf("\n === ERROR ===\n  Got: %lu  Expected: 1\n\n", got); failures++; }
		BN_free(a); BN_free(e); BN_free(m); BN_free(r); BN_CTX_free(ctx);
	}

	fflush(stdout);
	return failures;
}

/* --------------------------------------------------------------------- */
/*  MDC2 (used by Nagra / Nagra-AK7 / Seca smartcard readers)            */
/* --------------------------------------------------------------------- */
#ifdef WITH_LIB_MDC2
static int run_mdc2_tests(void)
{
	int failures = 0;
	printf("MDC2 test vectors\n");

	/* Empty input: output is just the initial state h||hh (0x52 x8 || 0x25 x8). */
	{
		MDC2_CTX c;
		uint8_t md[MDC2_DIGEST_LENGTH];
		MDC2_Init(&c);
		MDC2_Final(md, &c);
		printf(" Testing \"empty\"");
		if (hex_equal(md, MDC2_DIGEST_LENGTH,
			"52525252525252522525252525252525")) { printf(" [OK]\n"); }
		else { report_mismatch("MDC2", "empty", md, MDC2_DIGEST_LENGTH,
			"52525252525252522525252525252525"); failures++; }
	}

	/* Canonical KAT from OpenSSL 1.0 mdc2test.c:
	 *   input  = "Now is the time for all " (24 bytes, 3 blocks)
	 *   digest = 42e50cd224baceba760bdd2bd409281a  */
	{
		MDC2_CTX c;
		uint8_t md[MDC2_DIGEST_LENGTH];
		const char *msg = "Now is the time for all ";
		MDC2_Init(&c);
		MDC2_Update(&c, (const unsigned char *)msg, strlen(msg));
		MDC2_Final(md, &c);
		printf(" Testing \"Now is the time...\"");
		if (hex_equal(md, MDC2_DIGEST_LENGTH,
			"42e50cd224baceba760bdd2bd409281a")) { printf(" [OK]\n"); }
		else { report_mismatch("MDC2", "NBS", md, MDC2_DIGEST_LENGTH,
			"42e50cd224baceba760bdd2bd409281a"); failures++; }
	}

	/* Same again split mid-block to exercise the streaming buffer. */
	{
		MDC2_CTX c;
		uint8_t md[MDC2_DIGEST_LENGTH];
		const char *msg = "Now is the time for all ";
		MDC2_Init(&c);
		MDC2_Update(&c, (const unsigned char *)msg, 5);
		MDC2_Update(&c, (const unsigned char *)msg + 5, strlen(msg) - 5);
		MDC2_Final(md, &c);
		printf(" Testing \"Now is the time...\" streaming");
		if (hex_equal(md, MDC2_DIGEST_LENGTH,
			"42e50cd224baceba760bdd2bd409281a")) { printf(" [OK]\n"); }
		else { report_mismatch("MDC2 streaming", "NBS", md, MDC2_DIGEST_LENGTH,
			"42e50cd224baceba760bdd2bd409281a"); failures++; }
	}

	fflush(stdout);
	return failures;
}
#endif /* WITH_LIB_MDC2 */

/* --------------------------------------------------------------------- */
/*  IDEA (used by module-cccam key exchange + module-newcamd)            */
/* --------------------------------------------------------------------- */
#ifdef WITH_LIB_IDEA
static int run_idea_tests(void)
{
	int failures = 0;
	printf("IDEA test vectors\n");

	/* Lai/Massey original paper + Ascom spec vector:
	 *   key: 00010002 00030004 00050006 00070008
	 *   pt : 0000 0001 0002 0003
	 *   ct : 11fb ed2b 0198 6de5  */
	uint8_t key[16], pt[8], expct[8];
	hex_decode("00010002000300040005000600070008", key, sizeof(key));
	hex_decode("0000000100020003", pt, sizeof(pt));
	hex_decode("11fbed2b01986de5", expct, sizeof(expct));

	IDEA_KEY_SCHEDULE ks_e, ks_d;
	idea_set_encrypt_key(key, &ks_e);
	idea_set_decrypt_key(&ks_e, &ks_d);

	/* ECB encrypt one block */
	uint8_t got[8];
	idea_ecb_encrypt(pt, got, &ks_e);
	printf(" Testing \"Ascom KAT\" encrypt");
	if (memcmp(got, expct, 8) == 0) { printf(" [OK]"); }
	else { report_mismatch("IDEA enc", "Ascom", got, 8, "11fbed2b01986de5"); failures++; }

	/* ECB decrypt back */
	uint8_t back[8];
	idea_ecb_encrypt(expct, back, &ks_d);
	printf(" / decrypt");
	if (memcmp(back, pt, 8) == 0) { printf(" [OK]\n"); }
	else { report_mismatch("IDEA dec", "Ascom", back, 8, "0000000100020003"); failures++; }

	/* CBC reversal — 2 blocks with fresh IV each call */
	{
		uint8_t iv[8], iv_work[8];
		uint8_t cbc_pt[16], cbc_buf[16];
		hex_decode("48656c6c6f2c20494445412074657374", cbc_pt, sizeof(cbc_pt)); /* "Hello, IDEA test" */
		hex_decode("a1b2c3d4e5f6a7b8", iv, sizeof(iv));

		memcpy(cbc_buf, cbc_pt, 16);
		memcpy(iv_work, iv, 8);
		idea_cbc_encrypt(cbc_buf, cbc_buf, 16, &ks_e, iv_work, IDEA_ENCRYPT);
		memcpy(iv_work, iv, 8);
		idea_cbc_encrypt(cbc_buf, cbc_buf, 16, &ks_d, iv_work, IDEA_DECRYPT);
		printf(" Testing \"IDEA-CBC reversal\"");
		if (memcmp(cbc_buf, cbc_pt, 16) == 0) { printf(" [OK]\n"); }
		else { printf("\n === ERROR === IDEA-CBC reversal failed\n"); failures++; }
	}

	fflush(stdout);
	return failures;
}
#endif /* WITH_LIB_IDEA */

/* --------------------------------------------------------------------- */
/*  RC6 (used by module-cccam)                                           */
/* --------------------------------------------------------------------- */
#ifdef WITH_LIB_RC6
static int run_rc6_tests(void)
{
	int failures = 0;
	printf("RC6 test vectors\n");

	/* RC6-32/20/16 published reference vectors
	 * (Rivest, Robshaw, Sidney, Yin — RC6 spec paper, Appendix A). */
	struct {
		const char *name;
		const char *key_hex;
		const char *pt_hex;
		const char *ct_hex;
	} vec[] = {
		{ "all-zero", "00000000000000000000000000000000",
		              "00000000000000000000000000000000",
		              "8fc3a53656b1f778c129df4e9848a41e" },
		{ NULL, NULL, NULL, NULL }
	};
	for (int i = 0; vec[i].name; i++) {
		uint8_t key[16], pt[16], expct[16];
		RC6KEY S;
		uint32_t in[4], out[4];
		hex_decode(vec[i].key_hex, key, sizeof(key));
		hex_decode(vec[i].pt_hex, pt, sizeof(pt));
		hex_decode(vec[i].ct_hex, expct, sizeof(expct));
		rc6_key_setup(key, 16, S);

		/* RC6 API uses uint32_t arrays (little-endian words) */
		memcpy(in, pt, 16);
		rc6_block_encrypt(in, out, 1, S);
		memcpy(pt, out, 16);
		printf(" Testing \"%s\" encrypt", vec[i].name);
		if (memcmp(pt, expct, 16) == 0) { printf(" [OK]"); }
		else { report_mismatch("RC6 enc", vec[i].name, pt, 16, vec[i].ct_hex); failures++; }

		memcpy(in, expct, 16);
		rc6_block_decrypt(in, out, 1, S);
		memcpy(pt, out, 16);
		printf(" / decrypt");
		hex_decode(vec[i].pt_hex, expct, sizeof(expct));
		if (memcmp(pt, expct, 16) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("RC6 dec", vec[i].name, pt, 16, vec[i].pt_hex); failures++; }
	}

	fflush(stdout);
	return failures;
}
#endif /* WITH_LIB_RC6 */

/* --------------------------------------------------------------------- */
/*  Void* AES wrappers used by camd33/camd35/monitor/viaccess            */
/* --------------------------------------------------------------------- */
static int run_void_aes_tests(void)
{
	int failures = 0;
	printf("Void* AES wrappers (aes_cbc_encrypt / aes_cbc_decrypt)\n");

	/* Reuse NIST SP 800-38A F.2.1 AES-128-CBC vectors. The void* API
	 * operates in-place on buf and takes a caller-owned IV buffer. */
	char key_ascii[17];
	hex_decode("2b7e151628aed2a6abf7158809cf4f3c", (uint8_t *)key_ascii, 16);
	key_ascii[16] = '\0';

	uint8_t iv_ref[16], pt[32], ct_expct[32], work[32], iv_work[16];
	hex_decode("000102030405060708090a0b0c0d0e0f", iv_ref, 16);
	hex_decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
			   pt, 32);
	hex_decode("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2",
			   ct_expct, 32);

	struct aes_keys *ak = NULL;
	if (!aes_set_key_alloc(&ak, key_ascii)) {
		printf(" === ERROR === aes_set_key_alloc failed\n");
		return 1;
	}

	memcpy(work, pt, 32);
	memcpy(iv_work, iv_ref, 16);
	aes_cbc_encrypt(ak, work, 32, iv_work);
	printf(" Testing \"AES128-CBC (void*) NIST F.2.1\" encrypt");
	if (memcmp(work, ct_expct, 32) == 0) { printf(" [OK]"); }
	else { report_mismatch("aes_cbc_encrypt", "F.2.1", work, 32,
		"7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"); failures++; }

	memcpy(work, ct_expct, 32);
	memcpy(iv_work, iv_ref, 16);
	aes_cbc_decrypt(ak, work, 32, iv_work);
	printf(" / decrypt");
	if (memcmp(work, pt, 32) == 0) { printf(" [OK]\n"); }
	else { report_mismatch("aes_cbc_decrypt", "F.2.1", work, 32,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"); failures++; }

	/* aes_encrypt_idx / aes_decrypt: multi-block ECB (reuse NIST F.1.1 + blk2) */
	{
		uint8_t ecb_pt[32], ecb_expct[32], ecb_work[32];
		hex_decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
				   ecb_pt, 32);
		hex_decode("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf",
				   ecb_expct, 32);

		memcpy(ecb_work, ecb_pt, 32);
		aes_encrypt_idx(ak, ecb_work, 32);
		printf(" Testing \"AES128-ECB (void*) multi-block\" encrypt");
		if (memcmp(ecb_work, ecb_expct, 32) == 0) { printf(" [OK]"); }
		else { report_mismatch("aes_encrypt_idx", "F.1.1", ecb_work, 32,
			"3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"); failures++; }

		memcpy(ecb_work, ecb_expct, 32);
		aes_decrypt(ak, ecb_work, 32);
		printf(" / decrypt");
		if (memcmp(ecb_work, ecb_pt, 32) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("aes_decrypt", "F.1.1", ecb_work, 32,
			"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"); failures++; }
	}

	NULLFREE(ak);
	fflush(stdout);
	return failures;
}

/* --------------------------------------------------------------------- */
/*  Bignum: BN_bn2bin / BN_num_bytes / BN_mod_inverse                    */
/* --------------------------------------------------------------------- */
static int run_bn_extra_tests(void)
{
	int failures = 0;
	printf("Bignum extras (BN_bn2bin / BN_mod_inverse)\n");

	/* BN_num_bytes + BN_bn2bin: 0x12345678 is 4 bytes, portable on
	 * 32-bit ARM (BN_set_word's unsigned long is 32-bit there). */
	{
		BIGNUM *a = BN_new();
		BN_set_word(a, 0x12345678UL);
		int n = BN_num_bytes(a);
		printf(" Testing \"BN_num_bytes(0x12345678)\"");
		if (n == 4) { printf(" [OK]\n"); }
		else { printf("\n === ERROR === got %d, expected 4\n", n); failures++; }

		uint8_t out[16] = {0};
		int wrote = BN_bn2bin(a, out);
		printf(" Testing \"BN_bn2bin\"");
		if (wrote == 4 && hex_equal(out, 4, "12345678")) { printf(" [OK]\n"); }
		else { report_mismatch("BN_bn2bin", "u32", out, 4, "12345678"); failures++; }
		BN_free(a);
	}

	/* BN_mod_inverse: 7 * x ≡ 1 (mod 26) → x = 15  (7*15 = 105 = 4*26+1) */
	{
		BIGNUM *a = BN_new();
		BIGNUM *m = BN_new();
		BIGNUM *r = BN_new();
		BN_CTX *ctx = BN_CTX_new();
		BN_set_word(a, 7);
		BN_set_word(m, 26);
		BIGNUM *ret = BN_mod_inverse(r, a, m, ctx);
		unsigned long got = BN_get_word(r);
		printf(" Testing \"7^-1 mod 26\"");
		if (ret != NULL && got == 15) { printf(" [OK]\n"); }
		else { printf("\n === ERROR === got %lu, expected 15\n", got); failures++; }
		BN_free(a); BN_free(m); BN_free(r); BN_CTX_free(ctx);
	}

	/* BN_mul: 123 * 456 = 56088 */
	{
		BIGNUM *a = BN_new(), *b = BN_new(), *r = BN_new();
		BN_CTX *ctx = BN_CTX_new();
		BN_set_word(a, 123); BN_set_word(b, 456);
		BN_mul(r, a, b, ctx);
		printf(" Testing \"BN_mul(123, 456)\"");
		if (BN_get_word(r) == 56088) { printf(" [OK]\n"); }
		else { printf("\n === ERROR === got %lu, expected 56088\n", (unsigned long)BN_get_word(r)); failures++; }
		BN_free(a); BN_free(b); BN_free(r); BN_CTX_free(ctx);
	}

	/* BN_add_word / BN_sub_word / BN_cmp */
	{
		BIGNUM *a = BN_new(), *b = BN_new();
		BN_set_word(a, 1000);
		BN_add_word(a, 23);       /* 1023 */
		BN_sub_word(a, 500);      /* 523  */
		BN_set_word(b, 523);
		printf(" Testing \"BN_add_word / BN_sub_word / BN_cmp\"");
		if (BN_get_word(a) == 523 && BN_cmp(a, b) == 0) { printf(" [OK]\n"); }
		else { printf("\n === ERROR === a=%lu, cmp=%d\n", (unsigned long)BN_get_word(a), BN_cmp(a, b)); failures++; }
		BN_free(a); BN_free(b);
	}

	/* BN_copy */
	{
		BIGNUM *a = BN_new(), *b = BN_new();
		BN_set_word(a, 42);
		BN_copy(b, a);
		printf(" Testing \"BN_copy\"");
		if (BN_get_word(b) == 42 && BN_cmp(a, b) == 0) { printf(" [OK]\n"); }
		else { printf("\n === ERROR === b=%lu\n", (unsigned long)BN_get_word(b)); failures++; }
		BN_free(a); BN_free(b);
	}

	fflush(stdout);
	return failures;
}

/* --------------------------------------------------------------------- */
/*  Raw single-block DES via des() + schedule                      */
/* --------------------------------------------------------------------- */
#ifdef WITH_LIB_DES
static int run_des_raw_tests(void)
{
	int failures = 0;
	printf("Raw des() single-block test vectors\n");

	/* NBS FIPS 81 / Stallings:
	 *   K  = 133457799bbcdff1, PT = 0123456789abcdef, CT = 85e813540f0ab405 */
	uint8_t key[8], pt[8], expct[8], buf[8];
	hex_decode("133457799bbcdff1", key, sizeof(key));
	hex_decode("0123456789abcdef", pt, sizeof(pt));
	hex_decode("85e813540f0ab405", expct, sizeof(expct));

	uint32_t ks[32];
	des_set_key(key, ks);

	memcpy(buf, pt, 8);
	des(buf, ks, 1);
	printf(" Testing \"Stallings via des()\" encrypt");
	if (memcmp(buf, expct, 8) == 0) { printf(" [OK]"); }
	else { report_mismatch("des enc", "Stallings", buf, 8, "85e813540f0ab405"); failures++; }

	memcpy(buf, expct, 8);
	des(buf, ks, 0);
	printf(" / decrypt");
	if (memcmp(buf, pt, 8) == 0) { printf(" [OK]\n"); }
	else { report_mismatch("des dec", "Stallings", buf, 8, "0123456789abcdef"); failures++; }

	/* DES key-parity helpers */
	{
		uint8_t k[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
		uint8_t expected[8] = { 1, 1, 2, 2, 4, 4, 7, 7 };
		des_set_odd_parity(k);
		printf(" Testing \"des_set_odd_parity\"");
		if (memcmp(k, expected, 8) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("des_set_odd_parity", "small", k, 8, "0101020204040707"); failures++; }
	}
	{
		uint8_t k[16];
		for (int i = 0; i < 16; i++) k[i] = i;
		des_set_odd_parity_all(k, 16);
		printf(" Testing \"des_set_odd_parity_all(16)\"");
		bool ok = true;
		for (int i = 0; i < 16 && ok; i++) {
			uint8_t p = 0;
			for (int j = 0; j < 8; j++) p ^= (k[i] >> j) & 1;
			if (p != 1) ok = false;
		}
		if (ok) { printf(" [OK]\n"); }
		else { printf("\n === ERROR === parity not odd on all bytes\n"); failures++; }
	}

	fflush(stdout);
	return failures;
}
#endif /* WITH_LIB_DES */

/* --------------------------------------------------------------------- */
/*  aes_decrypt_from_list (per-reader AES key DB used by Viaccess/Conax) */
/* --------------------------------------------------------------------- */
#ifdef READER_VIACCESS
static int run_aes_key_list_tests(void)
{
	int failures = 0;
	printf("AES entry list (aes_decrypt_from_list / aes_present)\n");

	AES_ENTRY *list = NULL;
	uint8_t key1[16]; hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key1, 16);
	uint8_t key2[16]; hex_decode("000102030405060708090a0b0c0d0e0f", key2, 16);

	add_aes_entry(&list, 0x0500, 0x043800, 0, key1);
	add_aes_entry(&list, 0x0600, 0x070800, 1, key2);

	printf(" Testing \"aes_present(lookup hits)\"");
	int h1 = aes_present(list, 0x0500, 0x043800, 0);
	int h2 = aes_present(list, 0x0600, 0x070800, 1);
	int hmiss = aes_present(list, 0x1234, 0x000000, 0);
	if (h1 && h2 && !hmiss) { printf(" [OK]\n"); }
	else { printf("\n === ERROR === h1=%d h2=%d hmiss=%d\n", h1, h2, hmiss); failures++; }

	/* Encrypt a block with key1 (via AES_KEY), hand it to
	 * aes_decrypt_from_list with the matching caid/ident/keyid,
	 * expect plaintext back. */
	{
		uint8_t pt[16], ct[16];
		hex_decode("6bc1bee22e409f96e93d7e117393172a", pt, 16);
		AES_KEY ek;
		AES_set_encrypt_key(key1, 128, &ek);
		AES_encrypt(pt, ct, &ek);

		uint8_t work[16]; memcpy(work, ct, 16);
		int rc = aes_decrypt_from_list(list, 0x0500, 0x043800, 0, work, 16);
		printf(" Testing \"aes_decrypt_from_list round-trip\"");
		if (rc >= 0 && memcmp(work, pt, 16) == 0) { printf(" [OK]\n"); }
		else { report_mismatch("aes_decrypt_from_list", "rt", work, 16,
			"6bc1bee22e409f96e93d7e117393172a"); failures++; }
	}

	aes_clear_entries(&list);
	fflush(stdout);
	return failures;
}
#endif /* READER_VIACCESS */

/* --------------------------------------------------------------------- */
/*  AES-128-CBC decrypt chunked: verify IV chaining across multiple      */
/*  decrypt calls (each block decrypted individually with running IV).   */
/* --------------------------------------------------------------------- */
static int run_aes_cbc_dec_chunked(void)
{
	int failures = 0;
	printf("AES-128-CBC decrypt chunked (IV chaining)\n");

	uint8_t key[16], iv[16], ct[64], pt[64];
	hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
	hex_decode("000102030405060708090a0b0c0d0e0f", iv, 16);
	hex_decode("6bc1bee22e409f96e93d7e117393172a"
	           "ae2d8a571e03ac9c9eb76fac45af8e51"
	           "30c81c46a35ce411e5fbc1191a0a52ef"
	           "f69f2445df4f9b17ad2b417be66c3710", pt, 64);
	hex_decode("7649abac8119b246cee98e9b12e9197d"
	           "5086cb9b507219ee95db113a917678b2"
	           "73bed6b8e3c1743b7116e69e22229516"
	           "3ff1caa1681fac09120eca307586e1a7", ct, 64);

	uint8_t iv_local[16], got[64];
	memcpy(iv_local, iv, 16);
	AES_KEY dk;
	AES_set_decrypt_key(key, 128, &dk);
	memset(got, 0, sizeof(got));
	for (size_t off = 0; off < 64; off += 16)
		AES_cbc_encrypt(ct + off, got + off, 16, &dk, iv_local, AES_DECRYPT);

	printf(" Testing \"NIST F.2.1 decrypt-chunked\"");
	if (memcmp(got, pt, 64) == 0) { printf(" [OK]\n"); }
	else { report_mismatch("AES-CBC dec-chunked", "F.2.1", got, 64,
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"); failures++; }

	fflush(stdout);
	return failures;
}

/* --------------------------------------------------------------------- */
/*  __md5_crypt (webif password hashing)                                 */
/* --------------------------------------------------------------------- */
#ifdef WITH_LIB_MD5
static int run_md5_crypt_tests(void)
{
	int failures = 0;
	printf("MD5-crypt ($1$) webif password hashing\n");

	/* Verified reference: `openssl passwd -1 -salt 12345678 password`
	 * = $1$12345678$o2n/JiO/h5VviOInWJ4OQ/ */
	char out[64];
	__md5_crypt("password", "$1$12345678", out);
	printf(" Testing \"password/12345678\"");
	if (strcmp(out, "$1$12345678$o2n/JiO/h5VviOInWJ4OQ/") == 0) { printf(" [OK]\n"); }
	else { printf("\n === ERROR === got '%s', expected '$1$12345678$o2n/JiO/h5VviOInWJ4OQ/'\n", out); failures++; }

	fflush(stdout);
	return failures;
}
#endif

/* --------------------------------------------------------------------- */
/*  Entry point                                                          */
/* --------------------------------------------------------------------- */

static int run_crypto_tests(void)
{
	int failures = 0;
	printf("\n=== Crypto tests ===\n");

	failures += run_md5_tests();
#ifdef WITH_LIB_MD5
	failures += run_md5_crypt_tests();
#endif
	failures += run_sha1_tests();
	failures += run_sha1_input_tests();
	failures += run_sha256_tests();
#ifdef WITH_LIB_MDC2
	failures += run_mdc2_tests();
#endif
	failures += run_aes_ecb_tests();
	failures += run_aes_cbc_tests();
	failures += run_aesctx_tests();
	failures += run_void_aes_tests();
#ifdef WITH_LIB_IDEA
	failures += run_idea_tests();
#endif
#ifdef WITH_LIB_RC6
	failures += run_rc6_tests();
#endif
	failures += run_des_tests();
#ifdef WITH_LIB_DES
	failures += run_des_raw_tests();
#endif
	failures += run_aes_cbc_dec_chunked();
#ifdef READER_VIACCESS
	failures += run_aes_key_list_tests();
#endif
	failures += run_bn_tests();
	failures += run_bn_extra_tests();
	return failures;
}
int run_all_tests(void)
{
	int failures = 0;

	ECM_WHITELIST ecm_whitelist, ecm_whitelist_c;
	struct test_type ecm_whitelist_test =
	{
		.desc     = "ECM whitelist setting (READER: 'ecmwhitelist')",
		.data     = &ecm_whitelist,
		.data_c   = &ecm_whitelist_c,
		.data_sz  = sizeof(ecm_whitelist),
		.chk_fn   = &chk_ecm_whitelist_adapter,
		.mk_t_fn  = &mk_t_ecm_whitelist_adapter,
		.clear_fn = &clear_ecm_whitelist_adapter,
		.clone_fn = &clone_ecm_whitelist_adapter,
		.has_data_fn = &has_data_ecm_whitelist_adapter,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "0500@043800:70,6E,6C,66,7A,61,67,75,5D,6B;0600@070800:11,22,33,44,55,66;0700:AA,BB,CC,DD,EE;01,02,03,04;0123@456789:01,02,03,04" },
			{ .in = "0500@043800:70,6E,6C,66,7A,61,67,75,5D,6B" },
			{ .in = "0500@043800:70,6E,6C,66" },
			{ .in = "0500@043800:70,6E,6C" },
			{ .in = "0500@043800:70" },
			{ .in = "0500:81,82,83;0600:91" },
			{ .in = "0500:81,82" },
			{ .in = "0500:81" },
			{ .in = "@123456:81" },
			{ .in = "@123456:81;@000789:AA,BB,CC" },
			{ .in = "81" },
			{ .in = "81,82,83" },
			{ .in = "81,82,83,84" },
			{ .in = "0500@043800:70;0600@070800:11;0123@456789:01,02" },
			{ .in = "" },
			{ .in = "0500:81,32;0600:aa,bb", .out = "0500:81,32;0600:AA,BB" },
			{ .in = "500:1,2;60@77:a,b,z,,", .out = "0500:01,02;0060@000077:0A,0B" },
			{ .in = "@ff:81;@bb:11,22",      .out = "@0000FF:81;@0000BB:11,22" },
			{ .in = "@:81",                  .out = "81" },
			{ .in = "81;zzs;;;;;ab",         .out = "81,AB" },
			{ .in = ":@",                    .out = "" },
			{ .in = ",:,@,",                 .out = "" },
			{ .in = "@:",                    .out = "" },
			{ .in = "@:,,",                  .out = "" },
			{ .in = "@:;;;",                 .out = "" },
			{ .in = ",",                     .out = "" },
			{ .in = NULL },
		},
	};
	failures += run_parser_test(&ecm_whitelist_test);

	ECM_HDR_WHITELIST ecm_hdr_whitelist, ecm_hdr_whitelist_c;
	struct test_type ecm_hdr_whitelist_test =
	{
		.desc     = "ECM header whitelist setting (READER: 'ecmhdrwhitelist')",
		.data     = &ecm_hdr_whitelist,
		.data_c   = &ecm_hdr_whitelist_c,
		.data_sz  = sizeof(ecm_hdr_whitelist),
		.chk_fn   = &chk_ecm_hdr_whitelist_adapter,
		.mk_t_fn  = &mk_t_ecm_hdr_whitelist_adapter,
		.clear_fn = &clear_ecm_hdr_whitelist_adapter,
		.clone_fn = &clone_ecm_hdr_whitelist_adapter,
		.has_data_fn = &has_data_ecm_hdr_whitelist_adapter,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "1830@123456:80308F078D,81308F078D;1702@007878:807090C7000000011010008712078400,817090C7000000011010008713078400" },
			{ .in = "1830:80308F078D,81308F078D;1702:807090C7000000011010008712078400,817090C7000000011010008713078400" },
			{ .in = "813061006A00075C00,803061006A00075C00" },
			{ .in = "813061006A00075C00" },
			{ .in = "1122334455667788991011121314151617182021222324252627282930", .out = "1122334455667788991011121314151617182021" },
			{ .in = "1122334455667788991011121314151617182021ABC", .out = "" },
			{ .in = "9999@999999:1122334455667788991011121314151617182021,2233334455667788991011121314151617182021;AAAA@BBBBBB:1122334455667788991011121314151617182021" },
			{ .in = "0500:81,82,83;0600:91" },
			{ .in = "0500:81,82" },
			{ .in = "0500:81" },
			{ .in = "@123456:81" },
			{ .in = "@123456:81;@000789:AA,BB,CC" },
			{ .in = "81" },
			{ .in = "81,82,83" },
			{ .in = "81,82,83,84" },
			{ .in = "0500@043800:70;0600@070800:11;0123@456789:01,02" },
			{ .in = "" },
			{ .in = "00,82,83" },
			{ .in = "0500:81,32;0600:aa,bb", .out = "0500:81,32;0600:AA,BB" },
			{ .in = "@ff:81;@bb:11,22",      .out = "@0000FF:81;@0000BB:11,22" },
			{ .in = "0500:,,,;0060@000077:,,;0700:,;0800", .out = "0800" },
			{ .in = "@:81",                  .out = "81" },
			{ .in = "81;zzs;;;;;ab",         .out = "81,AB" },
			{ .in = "81,abc,ab",             .out = "81,AB" },
			{ .in = "81,zz,ab",              .out = "81,AB" },
			{ .in = "1830@123456:",          .out = "" },
			{ .in = "500:1,2;60@77:a,b,z,,", .out = "" },
			{ .in = ":@",                    .out = "" },
			{ .in = ",:,@,",                 .out = "" },
			{ .in = "@:",                    .out = "" },
			{ .in = "@:,,",                  .out = "" },
			{ .in = "@:;;;",                 .out = "" },
			{ .in = ",",                     .out = "" },
			{ .in = NULL },
		},
	};
	failures += run_parser_test(&ecm_hdr_whitelist_test);

	TUNTAB tuntab, tuntab_c;
	struct test_type tuntab_test =
	{
		.desc     = "Beta tunnel (tuntab) (ACCOUNT: 'betatunnel')",
		.data     = &tuntab,
		.data_c   = &tuntab_c,
		.data_sz  = sizeof(tuntab),
		.chk_fn   = &chk_tuntab_adapter,
		.mk_t_fn  = &mk_t_tuntab_adapter,
		.clear_fn = &clear_tuntab_adapter,
		.clone_fn = &clone_tuntab_adapter,
		.has_data_fn = &has_data_tuntab_adapter,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "1833.007A:1702,1833.007B:1702,1833.007C:1702,1833.007E:1702,1833.007F:1702,1833.0080:1702,1833.0081:1702,1833.0082:1702,1833.0083:1702,1833.0084:1702" },
			{ .in = "1833.007A:1702,1833.007B:1702,1833.007C:1702,1833.007E:1702" },
			{ .in = "1833.007A:1702" },
			{ .in = "" },
			{ .in = "1833.007A" },
			{ .in = "1833:1702",      .out = "" },
			{ .in = "1833",           .out = "" },
			{ .in = "zzzz.yyyy:tttt", .out = "" },
			{ .in = "zzzz.yyyy",      .out = "" },
			{ .in = ",",              .out = "" },
			{ .in = ".:",             .out = "" },
			{ .in = ":.,",            .out = "" },
			{ .in = NULL },
		},
	};
	failures += run_parser_test(&tuntab_test);

	FTAB ftab, ftab_c;
	struct test_type ftab_test =
	{
		.desc     = "Filters (ftab) (ACCOUNT: 'chid', 'ident'; READER: 'chid', 'ident', 'fallback_percaid', 'localcards')",
		.data     = &ftab,
		.data_c   = &ftab_c,
		.data_sz  = sizeof(ftab),
		.chk_fn   = &chk_ftab_adapter,
		.mk_t_fn  = &mk_t_ftab_adapter,
		.clear_fn = &clear_ftab_adapter,
		.clone_fn = &clone_ftab_adapter,
		.has_data_fn = &has_data_ftab_adapter,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "0100:123456,234567;0200:345678,456789" },
			{ .in = "183D:000000,005411" },
			{ .in = "183D:000000" },
			{ .in = "0100:000012" },
			{ .in = "0100:000012;0604:0000BA,000101,00010E,000141" },
			{ .in = "1234:234567;0010:345678,876543" },
			{ .in = "" },
			{ .in = "0200:eeee,tyut,1234", .out = "0200:00EEEE,001234" },
			{ .in = "0200:eeee,tyut",      .out = "0200:00EEEE" },
			{ .in = "1:0",                 .out = "0001:000000" },
			{ .in = "1:0,1,0",             .out = "0001:000000,000001,000000" },
			{ .in = "0:0",                 .out = "" },
			{ .in = "zzzz:",               .out = "" },
			{ .in = "yyyy:rrrr,qqqq",      .out = "" },
			{ .in = ",",                   .out = "" },
			{ .in = ",;,",                 .out = "" },
			{ .in = ";;;",                 .out = "" },
			{ .in = ".:",                  .out = "" },
			{ .in = ":.,",                 .out = "" },
			{ .in = ":;.,",                .out = "" },
			{ .in = ".:;,",                .out = "" },
			{ .in = NULL },
		},
	};
	failures += run_parser_test(&ftab_test);

	CAIDVALUETAB caidvaluetab, caidvaluetab_c;
	struct test_type caidvaluetab_test =
	{
		.desc     = "caidvaluetab (ACCOUNT: 'lb_nbest_percaid'; GLOBAL: 'lb_nbest_percaid', 'fallbacktimeout_percaid', 'lb_retrylimits', 'cacheex_mode1_delay')",
		.data     = &caidvaluetab,
		.data_c   = &caidvaluetab_c,
		.data_sz  = sizeof(caidvaluetab),
		.chk_fn   = &chk_caidvaluetab_adapter,
		.mk_t_fn  = &mk_t_caidvaluetab_adapter,
		.clear_fn = &clear_caidvaluetab_adapter,
		.clone_fn = &clone_caidvaluetab_adapter,
		.has_data_fn = &has_data_caidvaluetab_adapter,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "0100:4,0200:3,0300:2,0400:1" },
			{ .in = "0100:4,02:3,03:2,04:1,0500:9999" },
			{ .in = "0100:4" },
			{ .in = "01:4" },
			{ .in = "" },
			{ .in = "0500:10000",          .out = "" },
			{ .in = "0200:eeee,tyut,1234", .out = "0200:0" },
			{ .in = "0200:eeee,tyut",      .out = "0200:0" },
			{ .in = "1:0",                 .out = "01:0" },
			{ .in = "1:0,1,0",             .out = "01:0" },
			{ .in = "0500:10000",          .out = "" },
			{ .in = "0:0",                 .out = "" },
			{ .in = "zzzz:",               .out = "" },
			{ .in = "yyyy:rrrr,qqqq",      .out = "" },
			{ .in = ",",                   .out = "" },
			{ .in = ",:,",                 .out = "" },
			{ .in = ";:;",                 .out = "" },
			{ .in = ".:",                  .out = "" },
			{ .in = ":.,",                 .out = "" },
			{ .in = ":;.,",                .out = "" },
			{ .in = ".:;,",                .out = "" },
			{ .in = NULL },
		},
	};
	failures += run_parser_test(&caidvaluetab_test);

	CAIDTAB caidtab, caidtab_c;
	struct test_type caidtab_test =
	{
		.desc     = "caidtab (ACCOUNT: 'caid'; READER: 'caid'; GLOBAL: 'lb_noproviderforcaid', 'double_check_caid', 'cwcycle_check_caid')",
		.data     = &caidtab,
		.data_c   = &caidtab_c,
		.data_sz  = sizeof(caidtab),
		.chk_fn   = &chk_caidtab_adapter,
		.mk_t_fn  = &mk_t_caidtab_adapter,
		.clear_fn = &clear_caidtab_adapter,
		.clone_fn = &clone_caidtab_adapter,
		.has_data_fn = &has_data_caidtab_adapter,
		.test_vec = (const struct test_vec[])
		{
			{ .in = "0200&FFEE:0300" },
			{ .in = "0200&FF00:0300,0400&00FF:0500" },
			{ .in = "0200&FF00:0300,0400,0500:0600,0600&FF0F:1234" },
			{ .in = "0400&FF00:0500,0600" },
			{ .in = "0702,0722" },
			{ .in = "0702&FFDF" },
			{ .in = "0100" },
			{ .in = "01" },
			{ .in = "" },
			{ .in = "0500:10000",          .out = "0500" },
			{ .in = "1000&5FFFF5:0600",    .out = "1000&FFF5:0600" },
			{ .in = "10000:10000",         .out = "" },
			{ .in = "rrrr&zzzz:mmmm",      .out = "" },
			{ .in = "0:0",                 .out = "" },
			{ .in = "zzzz:",               .out = "" },
			{ .in = "yyyy:rrrr,qqqq",      .out = "" },
			{ .in = ",",                   .out = "" },
			{ .in = ",:,",                 .out = "" },
			{ .in = "&:&",                 .out = "" },
			{ .in = ".:",                  .out = "" },
			{ .in = ":.,",                 .out = "" },
			{ .in = ":&.,",                .out = "" },
			{ .in = ".:&,",                .out = "" },
			{ .in = NULL },
		},
	};
	failures += run_parser_test(&caidtab_test);

	failures += run_crypto_tests();

	printf("Summary: %d failure(s)\n", failures);
	return failures;
}
