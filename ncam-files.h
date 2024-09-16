#ifndef NCAM_FILES_H_
#define NCAM_FILES_H_

char *get_tmp_dir(void);
char *get_tmp_dir_filename(char *dest, size_t destlen, const char *filename);
bool file_exists(const char *filename);
int32_t file_copy(char *srcfile, char *destfile);
int32_t safe_overwrite_with_bak(char *destfile, char *temp_file, char *bakfile, int32_t forceBakOverWrite);
#ifdef MODULE_GBOX
char *get_gbox_filename(char *dest, size_t destlen, const char *filename);
#endif

#ifdef WITH_LIBCURL
#include <curl/curl.h>
struct MemoryStruct
{
	char *memory;
	size_t size;
};
size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
int curl(CURL *curl_handle, char *url);
#endif

#endif
