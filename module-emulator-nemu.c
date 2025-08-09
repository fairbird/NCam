#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "ncam-string.h"
#include "module-streamrelay.h"
#include "module-emulator-nemu.h"
#include "module-emulator-biss.h"
#include "module-emulator-cryptoworks.h"
#include "module-emulator-director.h"
#include "module-emulator-irdeto.h"
#include "module-emulator-nagravision.h"
#include "module-emulator-omnicrypt.h"
#include "module-emulator-powervu.h"
#include "module-emulator-viaccess.h"
#include "module-emulator-tvcas.h"
#ifdef WITH_LIBCURL
#include "ncam-files.h"
int32_t pvu_bucket;
struct pvu_reader pvurdr[CS_CLIENT_HASHBUCKETS];
#endif

// Shared functions

int8_t is_valid_dcw(uint8_t *dw)
{
	uint8_t i;

	for (i = 0; i < 8; i+= 4)
	{
		if (((dw[i] + dw[i + 1] + dw[i + 2]) & 0xFF) != dw[i + 3])
		{
			return 0;
		}
	}

	return 1;
}

int8_t char_to_bin(uint8_t *out, const char *in, uint32_t inLen)
{
	uint32_t i, tmp;

	for (i = 0; i < inLen / 2; i++)
	{
		if (sscanf(in + i * 2, "%02X", &tmp) != 1)
		{
			return 0;
		}
		out[i] = (uint8_t)tmp;
	}
	return 1;
}

void date_to_str(char *dateStr, uint8_t len, int8_t offset, uint8_t format)
{
	// Creates a formatted date string for use in various functions.
	// A positive or negative time offset (in hours) can be set as well
	// as the format of the output string.

	time_t rawtime;
	struct tm timeinfo;

	time(&rawtime);
	rawtime += (time_t) offset * 60 * 60; // Add a positive or negative offset
	localtime_r(&rawtime, &timeinfo);

	switch (format)
	{
		case 1:
			strftime(dateStr, len, "%c", &timeinfo);
			break;

		case 2:
			strftime(dateStr, len, "%F @ %R", &timeinfo);
			break;

		case 3:
			strftime(dateStr, len, "%y%m%d%H", &timeinfo);
			break;
	}
}

/*
 * Key DB
 *
 * The Emu reader gets keys from the NCam binary and the "SoftCam.Key" file.
 *
 * The keys are stored in structures of type "KeyDataContainer", one per CAS. Each
 * container points to a dynamically allocated array of type "KeyData", which holds
 * the actual keys. The array initially holds up to 64 keys (64 * KeyData), and it
 * is expanded by 16 every time it's filled with keys. The "KeyDataContainer" also
 * includes info about the number of keys it contains ("KeyCount") and the maximum
 * number of keys it can store ("KeyMax").
 *
 * The "KeyData" structure, on the other hand, stores the actual key information,
 * including the "identifier", "provider", "keyName", "key" and "keyLength". There
 * is also a "nextKey" pointer to a similar "KeyData" structure which is only used
 * for Irdeto multiple keys, in a linked list style structure. For all other CAS,
 * the "nextKey" is a "NULL" pointer.
 *
 * For storing keys, the "SetKey" function is used. Duplicate keys are not allowed.
 * When storing a key that is already present in the database, its "key" value is
 * updated with the new one. For reading keys from the database, the "FindKey"
 * function is used. To delete all keys in a container, the "DeleteKeysInContainer"
 * function can be called.
*/

char *emu_keyfile_path = NULL;

#ifdef WITH_LIBCURL
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
	return written;
}

char *down_softcam(struct s_reader *rdr)
{
	char *tempkey;
	int32_t ret = 0, i, len = cs_strlen(get_tmp_dir()) + cs_strlen(rdr->label) + 2;

	for(i = 0; i < (int32_t)cs_strlen(rdr->device) - 3; i++)
	{
		if(rdr->device[i] == 0x2e && (rdr->device[i + 1] == 0x4b || rdr->device[i + 1] == 0x6b) &&
			(rdr->device[i + 2] == 0x45 || rdr->device[i + 2] == 0x65) && (rdr->device[i + 3] == 0x59 || rdr->device[i + 3] == 0x79))
		{
			ret = 1;
		}
	}

	if(!ret) { return NULL; }

	if(cs_malloc(&tempkey, len))
	{
		uint32_t i;
		char tmp_label[sizeof(rdr->label)];
		for(i = 0; i < strlen(rdr->label); i++)
		{
			if(rdr->label[i] == '/')
			{
				tmp_label[i] = 0;
				break;
			}
			else
			{
				tmp_label[i] = rdr->label[i];
			}
		}

		snprintf(tempkey, len, "%s/%s", get_tmp_dir(), tmp_label);

		mkdir(tempkey, S_IRWXU);

		CURL *curl_handle;
		curl_global_init(CURL_GLOBAL_ALL);
		curl_handle = curl_easy_init(); // init the curl session
		FILE *fp;
		len += cs_strlen(EMU_KEY_FILENAME) + 1;
		char tmp[len];
		snprintf(tmp, len, "%s/%s", tempkey, EMU_KEY_FILENAME);

  		fp = fopen(tmp, "w"); // open the file
		if(fp)
		{
			curl_easy_setopt(curl_handle, CURLOPT_MAXFILESIZE, 524288L); // refuse to download if larger than 524288 bytes!
			curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data); // send all data to this function
			curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, fp); // write the page body to this file handle
			ret = curl(curl_handle, rdr->device);
			fclose(fp); // close the header file
			cs_log("Download key file: %s (%s)", rdr->device, tmp);
		}
		else
		{
			ret = 0;
			cs_log("ERROR: Can't open priority file %s", tmp);
		}
		curl_easy_cleanup(curl_handle); // cleanup curl stuff
		curl_global_cleanup();
		tempkey[cs_strlen(tempkey)] = '\0';
	}

	if (!ret)
	{
		return NULL;
	}
	else
	{
		return tempkey;
	}
}
#endif

void emu_set_keyfile_path(const char *path)
{
	uint32_t pathLength;

	if (emu_keyfile_path != NULL)
	{
		free(emu_keyfile_path);
	}

	pathLength = cs_strlen(path);
	emu_keyfile_path = (char *)malloc(pathLength + 1);
	if (emu_keyfile_path == NULL)
	{
		return;
	}
	cs_strncpy(emu_keyfile_path, path, pathLength + 1);
}

KeyDataContainer CwKeys = { NULL, 0, 0 };
KeyDataContainer ViKeys = { NULL, 0, 0 };
KeyDataContainer NagraKeys = { NULL, 0, 0 };
KeyDataContainer IrdetoKeys = { NULL, 0, 0 };
KeyDataContainer BissSWs = { NULL, 0, 0 };
KeyDataContainer Biss2Keys = { NULL, 0, 0 };
KeyDataContainer OmnicryptKeys = { NULL, 0, 0 };
KeyDataContainer PowervuKeys = { NULL, 0, 0 };
KeyDataContainer TandbergKeys = { NULL, 0, 0 };
KeyDataContainer StreamKeys = { NULL, 0, 0 };

KeyDataContainer *emu_get_key_container(char identifier)
{
	switch (identifier)
	{
		case 'W':
			return &CwKeys;
		case 'V':
			return &ViKeys;
		case 'N':
			return &NagraKeys;
		case 'I':
			return &IrdetoKeys;
		case 'F':
			return &BissSWs;
		case 'G':
			return &Biss2Keys;
		case 'O':
			return &OmnicryptKeys;
		case 'P':
			return &PowervuKeys;
		case 'T':
			return &TandbergKeys;
		case 'A':
			return &StreamKeys;
		default:
			return NULL;
	}
}

static void write_key_to_file(char identifier, uint32_t provider, const char *keyName, uint8_t *key,
								uint32_t keyLength, char *comment)
{
	char line[1200], dateText[100], filename[EMU_KEY_FILENAME_MAX_LEN + 1];
	char *path, *filepath, *keyValue;
	uint32_t pathLength;
	uint8_t fileNameLen = cs_strlen(EMU_KEY_FILENAME);
	struct dirent *pDirent;
	DIR *pDir;
	FILE *file = NULL;

	pathLength = cs_strlen(emu_keyfile_path);
	path = (char *)malloc(pathLength + 1);
	if (path == NULL)
	{
		return;
	}
	cs_strncpy(path, emu_keyfile_path, pathLength + 1);

	pathLength = cs_strlen(path);
	if (pathLength >= fileNameLen && strcasecmp(path + pathLength - fileNameLen, EMU_KEY_FILENAME) == 0)
	{
		// cut file name
		path[pathLength - fileNameLen] = '\0';
	}

	pathLength = cs_strlen(path);
	if (path[pathLength - 1] == '/' || path[pathLength - 1] == '\\')
	{
		// cut trailing /
		path[pathLength - 1] = '\0';
	}

	pDir = opendir(path);
	if (pDir == NULL)
	{
		cs_log("Cannot open key file path: %s", path);
		free(path);
		return;
	}

	while ((pDirent = readdir(pDir)) != NULL)
	{
		if (strcasecmp(pDirent->d_name, EMU_KEY_FILENAME) == 0)
		{
			cs_strncpy(filename, pDirent->d_name, sizeof(filename));
			break;
		}
	}
	closedir(pDir);

	if (pDirent == NULL)
	{
		cs_strncpy(filename, EMU_KEY_FILENAME, sizeof(filename));
	}

	pathLength = cs_strlen(path) + 1 + cs_strlen(filename) + 1;
	filepath = (char *)malloc(pathLength);
	if (filepath == NULL)
	{
		free(path);
		return;
	}
	snprintf(filepath, pathLength, "%s/%s", path, filename);
	free(path);

	cs_log("Writing key file: %s", filepath);

	file = fopen(filepath, "a");
	free(filepath);
	if (file == NULL)
	{
		return;
	}

	date_to_str(dateText, sizeof(dateText), 0, 1);

	keyValue = (char *)malloc((keyLength * 2) + 1);
	if (keyValue == NULL)
	{
		fclose(file);
		return;
	}
	cs_hexdump(0, key, keyLength, keyValue, (keyLength * 2) + 1);

	if (comment)
	{
		snprintf(line, sizeof(line), "\n%c %08X %s %s ; added by Emu %s %s",
					identifier, provider, keyName, keyValue, dateText, comment);
	}
	else
	{
		snprintf(line, sizeof(line), "\n%c %08X %s %s ; added by Emu %s",
					identifier, provider, keyName, keyValue, dateText);
	}

	cs_log("Key written: %c %08X %s %s", identifier, provider, keyName, keyValue);

	free(keyValue);

	fwrite(line, cs_strlen(line), 1, file);
	fclose(file);
}

int8_t emu_set_key(char identifier, uint32_t provider, char *keyName, uint8_t *orgKey, uint32_t keyLength,
					uint8_t writeKey, char *comment, struct s_reader *rdr)
{
	uint32_t i, j;
	uint8_t *tmpKey = NULL;
	KeyDataContainer *KeyDB;
	KeyData *tmpKeyData, *newKeyData;

	identifier = (char)toupper((int)identifier);

	KeyDB = emu_get_key_container(identifier);
	if (KeyDB == NULL)
	{
		return 0;
	}

	keyName = strtoupper(keyName);

	if (identifier == 'F') // Prepare BISS keys before saving to the db
	{
		// Convert legacy BISS "00" & "01" keynames
		if (0 == strcmp(keyName, "00") || 0 == strcmp(keyName, "01"))
		{
			keyName = "00000000";
		}

		// All keyNames should have a length of 8 after converting
		if (cs_strlen(keyName) != 8)
		{
			cs_log("WARNING: Wrong key format in %s: F %08X %s", EMU_KEY_FILENAME, provider, keyName);
			return 0;
		}

		// Verify date-coded keyName (if enabled), ignoring old (expired) keys
		if (rdr->emu_datecodedenabled)
		{
			char timeStr[9];
			date_to_str(timeStr, sizeof(timeStr), 0, 3);

			// Reject old date-coded keys, but allow our "00000000" evergreen label
			if (strcmp("00000000", keyName) != 0 && strcmp(timeStr, keyName) >= 0)
			{
				return 0;
			}
		}
	}

	// Fix checksum for BISS keys with a length of 6
	if (identifier == 'F' && keyLength == 6)
	{
		tmpKey = (uint8_t *)malloc(8 * sizeof(uint8_t));
		if(tmpKey == NULL)
		{
			return 0;
		}

		tmpKey[0] = orgKey[0];
		tmpKey[1] = orgKey[1];
		tmpKey[2] = orgKey[2];
		tmpKey[3] = ((orgKey[0] + orgKey[1] + orgKey[2]) & 0xFF);
		tmpKey[4] = orgKey[3];
		tmpKey[5] = orgKey[4];
		tmpKey[6] = orgKey[5];
		tmpKey[7] = ((orgKey[3] + orgKey[4] + orgKey[5]) & 0xFF);

		keyLength = 8;
	}
	else // All keys with a length of 8, including BISS
	{
		tmpKey = (uint8_t *)malloc(keyLength * sizeof(uint8_t));
		if (tmpKey == NULL)
		{
			return 0;
		}

		memcpy(tmpKey, orgKey, keyLength);
	}

	// Fix patched mgcamd format for Irdeto
	if (identifier == 'I' && provider < 0xFFFF)
	{
		provider = provider << 8;
	}

	// Key already exists on db, update its value
	for (i = 0; i < KeyDB->keyCount; i++)
	{
		if (KeyDB->EmuKeys[i].provider != provider)
		{
			continue;
		}

		// Don't match keyName (i.e. expiration date) for BISS1 and BISS2 mode 1/E sesssion words
		if (identifier != 'F' && strcmp(KeyDB->EmuKeys[i].keyName, keyName))
		{
			continue;
		}

		// Allow multiple keys for Irdeto
		if (identifier == 'I')
		{
			// Reject duplicates
			tmpKeyData = &KeyDB->EmuKeys[i];
			do
			{
				if (memcmp(tmpKeyData->key, tmpKey, tmpKeyData->keyLength < keyLength ? tmpKeyData->keyLength : keyLength) == 0)
				{
					free(tmpKey);
					return 0;
				}
				tmpKeyData = tmpKeyData->nextKey;
			}
			while(tmpKeyData != NULL);

			// Add new key
			newKeyData = (KeyData *)malloc(sizeof(KeyData));
			if (newKeyData == NULL)
			{
				free(tmpKey);
				return 0;
			}

			newKeyData->identifier = identifier;
			newKeyData->provider = provider;

			if (cs_strlen(keyName) < EMU_MAX_CHAR_KEYNAME)
			{
				cs_strncpy(newKeyData->keyName, keyName, EMU_MAX_CHAR_KEYNAME);
			}
			else
			{
				memcpy(newKeyData->keyName, keyName, EMU_MAX_CHAR_KEYNAME);
			}

			newKeyData->keyName[EMU_MAX_CHAR_KEYNAME - 1] = 0;
			newKeyData->key = tmpKey;
			newKeyData->keyLength = keyLength;
			newKeyData->nextKey = NULL;

			tmpKeyData = &KeyDB->EmuKeys[i];
			j = 0;

			while (tmpKeyData->nextKey != NULL)
			{
				if (j == 0xFE)
				{
					break;
				}
				tmpKeyData = tmpKeyData->nextKey;
				j++;
			}

			if (tmpKeyData->nextKey)
			{
				NULLFREE(tmpKeyData->nextKey->key);
				NULLFREE(tmpKeyData->nextKey);
			}
			tmpKeyData->nextKey = newKeyData;

			if (writeKey)
			{
				write_key_to_file(identifier, provider, keyName, tmpKey, keyLength, comment);
			}
		}
		else // identifier != 'I'
		{
			free(KeyDB->EmuKeys[i].key);
			KeyDB->EmuKeys[i].key = tmpKey;
			KeyDB->EmuKeys[i].keyLength = keyLength;

			if (identifier == 'F') // Update keyName (i.e. expiration date) for BISS
			{
				cs_strncpy(KeyDB->EmuKeys[i].keyName, keyName, EMU_MAX_CHAR_KEYNAME);
			}

			if (writeKey)
			{
				write_key_to_file(identifier, provider, keyName, tmpKey, keyLength, comment);
			}
		}
		return 1;
	}

	// Key does not exist on db
	if (KeyDB->keyCount + 1 > KeyDB->keyMax)
	{
		if (KeyDB->EmuKeys == NULL) // db is empty
		{
			KeyDB->EmuKeys = (KeyData *)malloc(sizeof(KeyData) * (KeyDB->keyMax + 64));
			if (KeyDB->EmuKeys == NULL)
			{
				free(tmpKey);
				return 0;
			}
			KeyDB->keyMax += 64;
		}
		else // db is full, expand it
		{
			tmpKeyData = (KeyData *)realloc(KeyDB->EmuKeys, sizeof(KeyData) * (KeyDB->keyMax + 16));
			if (tmpKeyData == NULL)
			{
				free(tmpKey);
				return 0;
			}
			KeyDB->EmuKeys = tmpKeyData;
			KeyDB->keyMax += 16;
		}
	}

	KeyDB->EmuKeys[KeyDB->keyCount].identifier = identifier;
	KeyDB->EmuKeys[KeyDB->keyCount].provider = provider;

	if (cs_strlen(keyName) < EMU_MAX_CHAR_KEYNAME)
	{
		cs_strncpy(KeyDB->EmuKeys[KeyDB->keyCount].keyName, keyName, EMU_MAX_CHAR_KEYNAME);
	}
	else
	{
		memcpy(KeyDB->EmuKeys[KeyDB->keyCount].keyName, keyName, EMU_MAX_CHAR_KEYNAME);
	}

	KeyDB->EmuKeys[KeyDB->keyCount].keyName[EMU_MAX_CHAR_KEYNAME - 1] = 0;
	KeyDB->EmuKeys[KeyDB->keyCount].key = tmpKey;
	KeyDB->EmuKeys[KeyDB->keyCount].keyLength = keyLength;
	KeyDB->EmuKeys[KeyDB->keyCount].nextKey = NULL;
	KeyDB->keyCount++;

	if (writeKey)
	{
		write_key_to_file(identifier, provider, keyName, tmpKey, keyLength, comment);
	}
	return 1;
}

int8_t emu_find_key(char identifier, uint32_t provider, uint32_t providerIgnoreMask, char *keyName,
					uint8_t *key, uint32_t maxKeyLength, uint8_t isCriticalKey, uint32_t keyRef,
					uint8_t matchLength, uint32_t *getProvider)
{
	uint32_t i;
	uint16_t j;
	uint8_t provider_matching_key_count = 0;
	KeyDataContainer *KeyDB;
	KeyData *tmpKeyData;

	KeyDB = emu_get_key_container(identifier);
	if (KeyDB == NULL)
	{
		return 0;
	}

	for (i = 0; i < KeyDB->keyCount; i++)
	{
		if ((KeyDB->EmuKeys[i].provider & ~providerIgnoreMask) != provider)
		{
			continue;
		}

		// Don't match keyName (i.e. expiration date) for BISS
		if (identifier != 'F' && strcmp(KeyDB->EmuKeys[i].keyName, keyName))
		{
			continue;
		}

		// "matchLength" cannot be used when multiple keys are allowed
		// for a single provider/keyName combination.
		// Currently this is the case only for Irdeto keys.
		if (matchLength && KeyDB->EmuKeys[i].keyLength != maxKeyLength)
		{
			continue;
		}

		if (providerIgnoreMask)
		{
			if (provider_matching_key_count < keyRef)
			{
				provider_matching_key_count++;
				continue;
			}
			else
			{
				keyRef = 0;
			}
		}

		tmpKeyData = &KeyDB->EmuKeys[i];

		j = 0;
		while (j < keyRef && tmpKeyData->nextKey != NULL)
		{
			j++;
			tmpKeyData = tmpKeyData->nextKey;
		}

		if (j == keyRef)
		{
			memcpy(key, tmpKeyData->key, tmpKeyData->keyLength > maxKeyLength ? maxKeyLength : tmpKeyData->keyLength);
			if (tmpKeyData->keyLength < maxKeyLength)
			{
				memset(key + tmpKeyData->keyLength, 0, maxKeyLength - tmpKeyData->keyLength);
			}

			// Report the keyName (i.e. expiration date) of the session word found
			if (identifier == 'F')
			{
				cs_strncpy(keyName, tmpKeyData->keyName, EMU_MAX_CHAR_KEYNAME);
			}

			if (getProvider != NULL)
			{
				(*getProvider) = tmpKeyData->provider;
			}
			return 1;
		}
		else
		{
			break;
		}
	}

	if (isCriticalKey)
	{
		cs_log("Key not found: %c %X %s", identifier, provider, keyName);
	}

	return 0;
}

int8_t emu_update_key(char identifier, uint32_t provider, char *keyName, uint8_t *key,
						uint32_t keyLength, uint8_t writeKey, char *comment)
{
	uint32_t keyRef = 0;
	uint8_t *tmpKey = (uint8_t *)malloc(sizeof(uint8_t) * keyLength);

	if (tmpKey == NULL)
	{
		return 0;
	}

	while (emu_find_key(identifier, provider, 0, keyName, tmpKey, keyLength, 0, keyRef, 0, NULL))
	{
		if (memcmp(tmpKey, key, keyLength) == 0)
		{
			free(tmpKey);
			return 0;
		}

		keyRef++;
	}

	free(tmpKey);
	return emu_set_key(identifier, provider, keyName, key, keyLength, writeKey, comment, NULL);
}

static int32_t delete_keys_in_container(char identifier)
{
	// Deletes all keys stored in memory for the specified identifier,
	// but keeps the container itself, re-initialized at { NULL, 0, 0 }.
	// Returns the count of deleted keys.

	uint32_t oldKeyCount, i;
	KeyData *tmpKeyData;
	KeyDataContainer *KeyDB = emu_get_key_container(identifier);

	if (KeyDB == NULL || KeyDB->EmuKeys == NULL || KeyDB->keyCount == 0)
	{
		return 0;
	}

	for (i = 0; i < KeyDB->keyCount; i++)
	{
		// For Irdeto multiple keys only (linked list structure)
		while (KeyDB->EmuKeys[i].nextKey != NULL)
		{
			tmpKeyData = KeyDB->EmuKeys[i].nextKey;
			KeyDB->EmuKeys[i].nextKey = KeyDB->EmuKeys[i].nextKey->nextKey;
			free(tmpKeyData->key); // Free key
			free(tmpKeyData); // Free KeyData
		}

		// For single keys (all identifiers, including Irdeto)
		free(KeyDB->EmuKeys[i].key); // Free key
	}

	// Free the KeyData array
	NULLFREE(KeyDB->EmuKeys);
	oldKeyCount = KeyDB->keyCount;
	KeyDB->keyCount = 0;
	KeyDB->keyMax = 0;

	return oldKeyCount;
}

void emu_clear_keydata(void)
{
	uint32_t total = 0;

	total  = CwKeys.keyCount;
	total += ViKeys.keyCount;
	total += NagraKeys.keyCount;
	total += IrdetoKeys.keyCount;
	total += BissSWs.keyCount;
	total += Biss2Keys.keyCount;
	total += OmnicryptKeys.keyCount;
	total += PowervuKeys.keyCount;
	total += TandbergKeys.keyCount;
	total += StreamKeys.keyCount;

	if (total != 0)
	{
		cs_log("Freeing keys in memory: W:%d V:%d N:%d I:%d F:%d G:%d O:%d P:%d T:%d A:%d",
				CwKeys.keyCount, ViKeys.keyCount, NagraKeys.keyCount, IrdetoKeys.keyCount, BissSWs.keyCount,
				Biss2Keys.keyCount, OmnicryptKeys.keyCount, PowervuKeys.keyCount, TandbergKeys.keyCount,
				StreamKeys.keyCount);

		delete_keys_in_container('W');
		delete_keys_in_container('V');
		delete_keys_in_container('N');
		delete_keys_in_container('I');
		delete_keys_in_container('F');
		delete_keys_in_container('G');
		delete_keys_in_container('O');
		delete_keys_in_container('P');
		delete_keys_in_container('T');
		delete_keys_in_container('A');
	}
}

uint8_t emu_read_keyfile(struct s_reader *rdr, const char *opath)
{
	char line[1200], keyName[EMU_MAX_CHAR_KEYNAME], keyString[1026], identifier;
	char *path, *filepath, filename[EMU_KEY_FILENAME_MAX_LEN + 1];
	uint32_t pathLength, provider, keyLength;
	uint8_t fileNameLen = cs_strlen(EMU_KEY_FILENAME);
	uint8_t *key;
	struct dirent *pDirent;
	DIR *pDir;
	FILE *file = NULL;

	pathLength = cs_strlen(opath);
	path = (char *)malloc(pathLength + 1);
	if (path == NULL)
	{
		return 0;
	}
	cs_strncpy(path, opath, pathLength + 1);

	pathLength = cs_strlen(path);
	if ((pathLength >= fileNameLen && strcasecmp(path + pathLength - fileNameLen, EMU_KEY_FILENAME) == 0) &&
		(rdr->device[0] != 0x68 && rdr->device[1] != 0x74 && rdr->device[2] != 0x74 && rdr->device[3] != 0x70))
	{
		// cut file name
		path[pathLength - fileNameLen] = '\0';
	}

	pathLength = cs_strlen(path);
	if (path[pathLength - 1] == '/' || path[pathLength - 1] == '\\')
	{
		// cut trailing /
		path[pathLength - 1] = '\0';
	}

	pDir = opendir(path);
	if (pDir == NULL)
	{
		cs_log("Cannot open key file path: %s", path);
		free(path);
		return 0;
	}

	while ((pDirent = readdir(pDir)) != NULL)
	{
		if (strcasecmp(pDirent->d_name, EMU_KEY_FILENAME) == 0)
		{
			cs_strncpy(filename, pDirent->d_name, sizeof(filename));
			break;
		}
	}
	closedir(pDir);

	if (pDirent == NULL)
	{
		cs_log("Key file not found in: %s", path);
		free(path);
		return 0;
	}

	pathLength = cs_strlen(path) + 1 + cs_strlen(filename) + 1;
	filepath = (char *)malloc(pathLength);
	if (filepath == NULL)
	{
		free(path);
		return 0;
	}
	snprintf(filepath, pathLength, "%s/%s", path, filename);
	free(path);

	cs_log("Reading key file: %s", filepath);

	file = fopen(filepath, "r");
	free(filepath);
	if (file == NULL)
	{
		return 0;
	}

#ifdef WITH_WI
	char tmp[1024] = { 0, };
	snprintf(tmp, 1023, "%s%c", opath, 'e');
	if(access(tmp, R_OK) == 0)
	{
		emu_set_keyfile_path(tmp);
	}
	else
	{
		emu_set_keyfile_path(opath);
	}
#else
	emu_set_keyfile_path(opath);
#endif

	while (fgets(line, 1200, file))
	{
		if (sscanf(line, "%c %8x %11s %1024s", &identifier, &provider, keyName, keyString) != 4)
		{
			continue;
		}

		keyLength = cs_strlen(keyString) / 2;
		key = (uint8_t *)malloc(keyLength);
		if (key == NULL)
		{
			fclose(file);
			return 0;
		}

		if (char_to_bin(key, keyString, cs_strlen(keyString))) // Conversion OK
		{
			emu_set_key(identifier, provider, keyName, key, keyLength, 0, NULL, rdr);
		}
		else // Non-hex characters in keyString
		{
			if ((identifier != ';' && identifier != '#' && // Skip warning for comments, etc.
				 identifier != '=' && identifier != '-' &&
				 identifier != ' ') &&
				!(identifier == 'F' && 0 == strncmp(keyString, "XXXXXXXXXXXX", 12))) // Skip warning for BISS 'Example key' lines
			{
				// Alert user regarding faulty line
				cs_log("WARNING: non-hex value in %s at %c %08X %s %s",
						EMU_KEY_FILENAME, identifier, provider, keyName, keyString);
			}
		}
		free(key);
	}
	fclose(file);

	return 1;
}

#if defined(WITH_SOFTCAM) && !defined(__APPLE__) && !defined(__ANDROID__)
extern uint8_t SoftCamKey_Data[]    __asm__("_binary_SoftCam_Key_start");
extern uint8_t SoftCamKey_DataEnd[] __asm__("_binary_SoftCam_Key_end");

void emu_read_keymemory(struct s_reader *rdr)
{
	char *keyData, *line, *saveptr, keyName[EMU_MAX_CHAR_KEYNAME], keyString[1026], identifier;
	uint32_t provider, keyLength;
	uint8_t *key;

	keyData = (char *)malloc(SoftCamKey_DataEnd - SoftCamKey_Data + 1);
	if (keyData == NULL)
	{
		return;
	}
	memcpy(keyData, SoftCamKey_Data, SoftCamKey_DataEnd - SoftCamKey_Data);
	keyData[SoftCamKey_DataEnd-SoftCamKey_Data] = 0x00;

	line = strtok_r(keyData, "\n", &saveptr);
	while (line != NULL)
	{
		if (sscanf(line, "%c %8x %11s %1024s", &identifier, &provider, keyName, keyString) != 4)
		{
			line = strtok_r(NULL, "\n", &saveptr);
			continue;
		}

		keyLength = cs_strlen(keyString) / 2;

		key = (uint8_t *)malloc(keyLength);
		if (key == NULL)
		{
			free(keyData);
			return;
		}

		if (char_to_bin(key, keyString, cs_strlen(keyString))) // Conversion OK
		{
			emu_set_key(identifier, provider, keyName, key, keyLength, 0, NULL, rdr);
		}
		else // Non-hex characters in keyString
		{
			if ((identifier != ';' && identifier != '#' && // Skip warning for comments, etc.
				 identifier != '=' && identifier != '-' &&
				 identifier != ' ') &&
				!(identifier == 'F' && 0 == strncmp(keyString, "XXXXXXXXXXXX", 12))) // Skip warning for BISS 'Example key' lines
			{
				// Alert user regarding faulty line
				cs_log("WARNING: non-hex value in internal keyfile at %c %08X %s %s",
						identifier, provider, keyName, keyString);
			}
		}
		free(key);
		line = strtok_r(NULL, "\n", &saveptr);
	}
	free(keyData);
}
#else
void emu_read_keymemory(struct s_reader *UNUSED(rdr)) { }
#endif

static const char *get_error_reason(int8_t result)
{
	switch (result)
	{
		case EMU_OK:
			return "No error";

		case EMU_NOT_SUPPORTED:
			return "Not supported";

		case EMU_KEY_NOT_FOUND:
			return "Key not found";

		case EMU_KEY_REJECTED:
			return "ECM key rejected";

		case EMU_CORRUPT_DATA:
			return "Corrupt data";

		case EMU_CW_NOT_FOUND:
			return "CW not found";

		case EMU_CHECKSUM_ERROR:
			return "Checksum error";

		case EMU_OUT_OF_MEMORY:
			return "Out of memory";

		default:
			return "Unknown reason";
	}
}

int8_t emu_process_ecm(struct s_reader *rdr, const ECM_REQUEST *er, uint8_t *cw, EXTENDED_CW *cw_ex)
{
	if (er->ecmlen < 3)
	{
		cs_log_dbg(D_TRACE, "Received ecm data of zero length!");
		return 4;
	}

	uint16_t ecmLen = SCT_LEN(er->ecm);
	uint8_t ecmCopy[ecmLen];
	int8_t result = 1;

	if (ecmLen != er->ecmlen)
	{
		cs_log_dbg(D_TRACE, "Actual ecm data length 0x%03X but ecm section length is 0x%03X",
							er->ecmlen, ecmLen);
		return 4;
	}

	if (ecmLen > EMU_MAX_ECM_LEN)
	{
		cs_log_dbg(D_TRACE, "Actual ecm data length 0x%03X but maximum supported ecm length is 0x%03X",
							er->ecmlen, EMU_MAX_ECM_LEN);
		return 1;
	}
	
	if ((er->caid & 0xFF00) == 0x0B00)
	{
		if (er->ecmlen == 55 && rdr->ecm_master_key_length == 32)
		{
			if (ecm_decrypt_cw(rdr, er->ecm, er->ecmlen, cw) == 1)
			{
				return 0;
			}
		}
		else
		{
			cs_log_dbg(D_TRACE, "TVCAS: Invalid ECM length (%d) or no master key for CAID 0x%04X", 
					   er->ecmlen, er->caid);
		}
	}

	memcpy(ecmCopy, er->ecm, ecmLen);

		 if (caid_is_viaccess(er->caid))    result = viaccess_ecm(ecmCopy, cw);
	else if (caid_is_irdeto(er->caid))      result = irdeto2_ecm(er->caid, ecmCopy, cw);
	else if (caid_is_cryptoworks(er->caid)) result = cryptoworks_ecm(er->caid, ecmCopy, cw);
	else if (caid_is_powervu(er->caid))
	{
#ifdef WITH_LIBCURL
		if((strncmp(rdr->label, "linuxsat-support.com", 20) == 0) || (strncmp(rdr->label, "github:", 7) == 0))
		{
			pvu_bucket = (uintptr_t)rdr->client / 16 % CS_CLIENT_HASHBUCKETS; // Fixme: For Android this value is 0 (...???)
			cs_log_dbg(D_ATR|D_READER, "Reader label: %s client bucket: %d", rdr->label, pvu_bucket);
		}
		else { pvu_bucket = 0; }
		struct pvu_reader *pvu = &pvurdr[pvu_bucket];
#ifdef __ANDROID__ // Fixme: android
		pvu->rdr = rdr;
#else
		if(pvu_bucket == 0) { pvu->rdr = NULL; }
		else { pvu->rdr = rdr; }
#endif
#endif
		result = powervu_ecm(ecmCopy, cw, cw_ex, er->srvid, er->caid, er->tsid, er->onid, er->ens
#ifdef MODULE_STREAMRELAY
				, NULL
#endif
			);
	}
	else if (caid_is_director(er->caid))    result = director_ecm(ecmCopy, cw);
	else if (caid_is_nagra(er->caid))       result = nagra2_ecm(ecmCopy, cw);
	else if (caid_is_biss(er->caid))        result = biss_ecm(rdr, er->ecm, er->caid, er->pid, cw, cw_ex);
	else if (er->caid == 0x00FF)			result = omnicrypt_ecm(ecmCopy, cw); // temp caid

	if (result != 0)
	{
		cs_log("ECM failed: %s", get_error_reason(result));
	}

	return result;
}

int8_t emu_process_emm(struct s_reader *rdr, uint16_t caid, const uint8_t *emm, uint32_t *keysAdded)
{
	uint16_t emmLen = SCT_LEN(emm);
	uint8_t emmCopy[emmLen];
	int8_t result = 1;

	if (emmLen > EMU_MAX_EMM_LEN)
	{
		return 1;
	}
	memcpy(emmCopy, emm, emmLen);
	*keysAdded = 0;

	     if (caid_is_viaccess(caid))     result = viaccess_emm(emmCopy, keysAdded);
	else if (caid_is_irdeto(caid))       result = irdeto2_emm(caid, emmCopy, keysAdded);
	else if (caid_is_powervu(caid))      result = powervu_emm(emmCopy, keysAdded);
	else if (caid_is_director(caid))     result = director_emm(emmCopy, keysAdded);
#ifdef WITH_LIBCRYPTO
	else if (caid_is_biss_dynamic(caid)) result = biss_emm(rdr, emmCopy, keysAdded);
#else
	else if (caid_is_biss_dynamic(caid)) cs_log("%s biss emm not built in!", rdr->label);
#endif
	if (result != 0)
	{
		cs_log_dbg(D_EMM,"EMM failed: %s", get_error_reason(result));
	}

	return result;
}

#endif // WITH_EMU
