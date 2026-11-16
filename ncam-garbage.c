#define MODULE_LOG_PREFIX "gc"

#include "globals.h"
#include "ncam-garbage.h"
#include "ncam-lock.h"
#include "ncam-string.h"
#include "ncam-time.h"

#define HASH_BUCKETS 256
#define BUCKET_MASK (HASH_BUCKETS - 1)

struct cs_garbage
{
	time_t time;
	void *data;
#ifdef WITH_DEBUG
	char *file;
	uint32_t line;
#endif
	struct cs_garbage *next;
};

static struct cs_garbage *garbage_first[HASH_BUCKETS];
static CS_MUTEX_LOCK garbage_lock[HASH_BUCKETS];
static pthread_t garbage_thread;
static uint32_t garbage_counter;
static int32_t garbage_collector_active;
static int32_t garbage_adders_inflight;
static int32_t garbage_debug;
static pthread_mutex_t garbage_state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t garbage_state_cond = PTHREAD_COND_INITIALIZER;

static time_t garbage_time(void)
{
	struct timespec now;
	return clock_gettime(CLOCK_MONOTONIC, &now) == 0 ? now.tv_sec : (time_t)-1;
}

static int32_t garbage_collector_is_active(void)
{
	int32_t active;
	SAFE_MUTEX_LOCK(&garbage_state_lock);
	active = garbage_collector_active;
	SAFE_MUTEX_UNLOCK(&garbage_state_lock);
	return active;
}

static void garbage_collector_set_active(int32_t active)
{
	SAFE_MUTEX_LOCK(&garbage_state_lock);
	garbage_collector_active = active;
	SAFE_MUTEX_UNLOCK(&garbage_state_lock);
}

static int32_t garbage_add_ref(uint32_t *bucket)
{
	int32_t active;
	SAFE_MUTEX_LOCK(&garbage_state_lock);
	active = garbage_collector_active;
	if(active)
	{
		garbage_adders_inflight++;
		*bucket = garbage_counter++ & BUCKET_MASK;
	}
	SAFE_MUTEX_UNLOCK(&garbage_state_lock);
	return active;
}

static void garbage_add_unref(void)
{
	SAFE_MUTEX_LOCK(&garbage_state_lock);
	garbage_adders_inflight--;
	if(!garbage_collector_active && garbage_adders_inflight == 0)
	{
		SAFE_COND_SIGNAL(&garbage_state_cond);
	}
	SAFE_MUTEX_UNLOCK(&garbage_state_lock);
}

#ifdef WITH_DEBUG
void add_garbage_debug(void *data, char *file, uint32_t line)
{
#else
void add_garbage(void *data)
{
#endif
	if(!data)
		{ return; }

	if(garbage_debug == 1)
	{
		NULLFREE(data);
		return;
	}

	uint32_t bucket;
	if(!garbage_add_ref(&bucket))
	{
		NULLFREE(data);
		return;
	}

	struct cs_garbage *garbage = (struct cs_garbage*)malloc(sizeof(struct cs_garbage));
	if(garbage == NULL)
	{
		cs_log("*** MEMORY FULL -> FREEING DIRECT MAY LEAD TO INSTABILITY!!! ***");
		garbage_add_unref();
		NULLFREE(data);
		return;
	}
	garbage->data = data;
	garbage->next = NULL;
#ifdef WITH_DEBUG
	garbage->file = file;
	garbage->line = line;
#endif

	cs_writelock(__func__, &garbage_lock[bucket]);

#ifdef WITH_DEBUG
	if(garbage_debug == 2)
	{
		struct cs_garbage *garbagecheck = garbage_first[bucket];
		while(garbagecheck)
		{
			if(garbagecheck->data == data)
			{
				cs_log("Found a try to add garbage twice. Not adding the element to garbage list...");
				cs_log("Current garbage addition: %s, line %d.", file, line);
				cs_log("Original garbage addition: %s, line %d.", garbagecheck->file, garbagecheck->line);
				cs_writeunlock(__func__, &garbage_lock[bucket]);
				garbage_add_unref();
				NULLFREE(garbage);
				return;
			}
			garbagecheck = garbagecheck->next;
		}
	}
#endif

	garbage->time = garbage_time();
	garbage->next = garbage_first[bucket];
	garbage_first[bucket] = garbage;

	cs_writeunlock(__func__, &garbage_lock[bucket]);
	garbage_add_unref();
}

static pthread_cond_t sleep_cond;
static pthread_mutex_t sleep_cond_mutex;

static void garbage_collector(void)
{
	int32_t i;
	struct cs_garbage *garbage, *next;
	set_thread_name(__func__);

	while(garbage_collector_is_active())
	{
		time_t now = garbage_time();
		if(now == (time_t)-1)
		{
			sleepms_on_cond(__func__, &sleep_cond_mutex, &sleep_cond, 500);
			continue;
		}
		uint64_t retention = ((uint64_t)cfg.ctimeout * 2) / 1000 + 6;
		time_t deltime = now - (time_t)retention;

		for(i = 0; i < HASH_BUCKETS; ++i)
		{
			cs_writelock(__func__, &garbage_lock[i]);
			struct cs_garbage *expired = NULL;
			struct cs_garbage **link = &garbage_first[i];

			while((garbage = *link))
			{
				// Failed timestamp reads leave the entry for shutdown cleanup.
				if(garbage->time != (time_t)-1 && garbage->time < deltime)
				{
					*link = garbage->next;
					garbage->next = expired;
					expired = garbage;
				}
				else
				{
					link = &garbage->next;
				}
			}

			cs_writeunlock(__func__, &garbage_lock[i]);

			// Entries have been detached, no lock needed for freeing.
			while(expired)
			{
				next = expired->next;
				free(expired->data);
				free(expired);
				expired = next;
			}
		}
		sleepms_on_cond(__func__, &sleep_cond_mutex, &sleep_cond, 500);
	}
	pthread_exit(NULL);
}

void start_garbage_collector(int32_t debug)
{
	int32_t i;
	garbage_debug = debug;
	garbage_counter = 0;
	garbage_adders_inflight = 0;

	for(i = 0; i < HASH_BUCKETS; ++i)
	{
		cs_lock_create(__func__, &garbage_lock[i], "garbage_lock", 9000);
		garbage_first[i] = NULL;
	}

	cs_pthread_cond_init(__func__, &sleep_cond_mutex, &sleep_cond);

	garbage_collector_set_active(1);

	if(start_thread("garbage", (void *)&garbage_collector, NULL, &garbage_thread, 0, 1))
	{
		cs_exit(1);
	}
}

void stop_garbage_collector(void)
{
	if(garbage_collector_is_active())if(garbage_collector_active)
	{
		int32_t i;

		/* Set inactive and wait under the same lock so no new adders can race
		 * in between the flag flip and the inflight-drain check. */
		SAFE_MUTEX_LOCK(&garbage_state_lock);
		garbage_collector_active = 0;
		while(garbage_adders_inflight > 0)
		{
			SAFE_COND_WAIT(&garbage_state_cond, &garbage_state_lock);
		}
		SAFE_MUTEX_UNLOCK(&garbage_state_lock);

		SAFE_COND_SIGNAL(&sleep_cond);
		cs_sleepms(300);
		SAFE_COND_SIGNAL(&sleep_cond);
		SAFE_THREAD_JOIN(garbage_thread, NULL);

		for(i = 0; i < HASH_BUCKETS; ++i)
			{ cs_writelock(__func__, &garbage_lock[i]); }

		for(i = 0; i < HASH_BUCKETS; ++i)
		{
			while(garbage_first[i])
			{
				struct cs_garbage *next = garbage_first[i]->next;
				NULLFREE(garbage_first[i]->data);
				NULLFREE(garbage_first[i]);
				garbage_first[i] = next;
			}
		}

		for(i = 0; i < HASH_BUCKETS; ++i)
		{
			cs_writeunlock(__func__, &garbage_lock[i]);
			cs_lock_destroy(__func__, &garbage_lock[i]);
		}

		pthread_cond_destroy(&sleep_cond);
		pthread_mutex_destroy(&sleep_cond_mutex);
	}
}
