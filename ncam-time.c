#include "globals.h"
#include "ncam-time.h"

#if defined(CLOCKFIX)
struct timeval lasttime; // holds previous time to detect systemtime adjustments due to eg transponder change on dvb receivers
#endif

int64_t comp_timeb(struct timeb *tpa, struct timeb *tpb)
{
	return (int64_t)(((int64_t)(tpa->time - tpb->time) * 1000ull) + ((int64_t) tpa->millitm - (int64_t) tpb->millitm));
}

int64_t comp_timebus(struct timeb *tpa, struct timeb *tpb)
{
	return (int64_t)(((int64_t)(tpa->time - tpb->time) * 1000000ull) + ((int64_t) tpa->millitm - (int64_t) tpb->millitm));
}

/* Checks if year is a leap year. If so, 1 is returned, else 0. */
static int8_t is_leap(unsigned int y)
{
	return (y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0);
}

/* Drop-in replacement for timegm function as some plattforms strip the function from their libc.. */
time_t cs_timegm(struct tm *tm)
{
	time_t result = 0;
	int32_t i;

	if(tm->tm_mon > 12 || tm->tm_mon < 0 || tm->tm_mday > 31 || tm->tm_min > 60 || tm->tm_sec > 60 || tm->tm_hour > 24)
	{
		return 0;
	}

	for(i = 70; i < tm->tm_year; ++i)
	{
		result += is_leap(i + 1900) ? 366 : 365;
	}

	for(i = 0; i < tm->tm_mon; ++i)
	{
		if(i == 0 || i == 2 || i == 4 || i == 6 || i == 7 || i == 9 || i == 11) { result += 31; }
		else if(i == 3 || i == 5 || i == 8 || i == 10) { result += 30; }
		else if(is_leap(tm->tm_year + 1900)) { result += 29; }
		else { result += 28; }
	}

	result += tm->tm_mday - 1;
	result *= 24;
	result += tm->tm_hour;
	result *= 60;
	result += tm->tm_min;
	result *= 60;
	result += tm->tm_sec;
	return result;
}

/* Drop-in replacement for gmtime_r as some plattforms strip the function from their libc. */
struct tm *cs_gmtime_r(const time_t *timep, struct tm *r)
{
	static const int16_t daysPerMonth[13] =
	{
		0,
		31,
		31 + 28,
		31 + 28 + 31,
		31 + 28 + 31 + 30,
		31 + 28 + 31 + 30 + 31,
		31 + 28 + 31 + 30 + 31 + 30,
		31 + 28 + 31 + 30 + 31 + 30 + 31,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31
	};

	time_t i;
	time_t work = * timep % 86400;
	r->tm_sec = work % 60;
	work /= 60;
	r->tm_min = work % 60;
	r->tm_hour = work / 60;
	work = * timep / 86400;
	r->tm_wday = (4 + work) % 7;

	for(i = 1970; ; ++i)
	{
		time_t k = is_leap(i) ? 366 : 365;
		if(work >= k)
		{
			work -= k;
		}
		else
		{
			break;
		}
	}

	r->tm_year = i - 1900;
	r->tm_yday = work;
	r->tm_mday = 1;

	if(is_leap(i) && work > 58)
	{
		if(work == 59)
		{
			r->tm_mday = 2; /* 29.2. */
		}
		work -= 1;
	}

	for(i = 11; i && daysPerMonth[i] > work; --i) { ; }
	r->tm_mon = i;
	r->tm_mday += work - daysPerMonth[i];
	return r;
}

/* Drop-in replacement for ctime_r as some plattforms strip the function from their libc. */
char *cs_ctime_r(const time_t *timep, char *buf)
{
	struct tm t;
	localtime_r(timep, &t);
	strftime(buf, 26, "%c\n", &t);
	return buf;
}

void cs_ftime(struct timeb *tp)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
#if defined(CLOCKFIX)
	if (tv.tv_sec > lasttime.tv_sec || (tv.tv_sec == lasttime.tv_sec && tv.tv_usec >= lasttime.tv_usec)) // check for time issues!
	{
		lasttime = tv; // register this valid time
	}
	else
	{
		tv = lasttime;
		settimeofday(&tv, NULL); // set time back to last known valid time
		//fprintf(stderr, "*** WARNING: BAD TIME AFFECTING WHOLE NCAM ECM HANDLING, SYSTEMTIME SET TO LAST KNOWN VALID TIME **** \n");
	}
#endif
	tp->time = tv.tv_sec;
	tp->millitm = tv.tv_usec / 1000;
}

void cs_ftimeus(struct timeb *tp)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
#if defined(CLOCKFIX)
	if (tv.tv_sec > lasttime.tv_sec || (tv.tv_sec == lasttime.tv_sec && tv.tv_usec >= lasttime.tv_usec)) // check for time issues!
	{
		lasttime = tv; // register this valid time
	}
	else
	{
		tv = lasttime;
		settimeofday(&tv, NULL); // set time back to last known valid time
		//fprintf(stderr, "*** WARNING: BAD TIME AFFECTING WHOLE NCAM ECM HANDLING, SYSTEMTIME SET TO LAST KNOWN VALID TIME **** \n");
	}
#endif
	tp->time = tv.tv_sec;
	tp->millitm = tv.tv_usec;
}

void cs_sleepms(uint32_t msec)
{
	// does not interfere with signals like sleep and usleep do
	struct timespec req_ts, rem_ts;
	req_ts.tv_sec = msec / 1000;
	req_ts.tv_nsec = (msec % 1000) * 1000000L;
	int32_t olderrno = errno; // Some OS (especially MacOSX) seem to set errno to ETIMEDOUT when sleeping
	while (nanosleep(&req_ts, &rem_ts) == -1 && errno == EINTR)
	{
		req_ts = rem_ts;
	}
	errno = olderrno;
}

void cs_sleepus(uint32_t usec)
{
	// does not interfere with signals like sleep and usleep do
	struct timespec req_ts, rem_ts;
	req_ts.tv_sec = usec / 1000000;
	req_ts.tv_nsec = (usec % 1000000) * 1000L;
	int32_t olderrno = errno; // Some OS (especially MacOSX) seem to set errno to ETIMEDOUT when sleeping

	while (nanosleep(&req_ts, &rem_ts) == -1 && errno == EINTR)
	{
		req_ts = rem_ts;
	}
	errno = olderrno;
}

void add_ms_to_timespec(struct timespec *timeout, int32_t msec)
{
	struct timespec now;
	int64_t nanosecs, secs;
	const int64_t NANOSEC_PER_MS = 1000000;
	const int64_t NANOSEC_PER_SEC = 1000000000;
	cs_gettime(&now);
	nanosecs = (int64_t) (msec * NANOSEC_PER_MS + now.tv_nsec);
	if (nanosecs >= NANOSEC_PER_SEC)
	{
		secs = now.tv_sec + (nanosecs / NANOSEC_PER_SEC);
		nanosecs %= NANOSEC_PER_SEC;
	}
	else
	{
		secs = now.tv_sec;
	}
	timeout->tv_sec = (long)secs;
	timeout->tv_nsec = (long)nanosecs;
}

void add_ms_to_timeb(struct timeb *tb, int32_t ms)
{
	if (ms >= 1000){
		tb->time += ms / 1000;
		tb->millitm += (ms % 1000);
	}
	else{
		tb->millitm += ms;
	}
	if(tb->millitm >= 1000)
	{
		tb->millitm %= 1000;
		tb->time++;
	}
}

int64_t add_ms_to_timeb_diff(struct timeb *tb, int32_t ms)
{
	struct timeb tb_now;
	add_ms_to_timeb(tb, ms);
	cs_ftime(&tb_now);
	return comp_timeb(tb, &tb_now);
}

void __cs_pthread_cond_init(const char *n, pthread_cond_t *cond)
{
	pthread_condattr_t attr;
	SAFE_CONDATTR_INIT_R(&attr, n); // init condattr with defaults
	SAFE_COND_INIT_R(cond, &attr, n); // init thread with right clock assigned
	pthread_condattr_destroy(&attr);
}

void __cs_pthread_cond_init_nolog(const char *n, pthread_cond_t *cond)
{
	pthread_condattr_t attr;
	SAFE_CONDATTR_INIT_NOLOG_R(&attr, n); // init condattr with defaults
	SAFE_COND_INIT_NOLOG_R(cond, &attr, n); // init thread with right clock assigned
	pthread_condattr_destroy(&attr);
}

void sleepms_on_cond(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond, uint32_t msec)
{
	struct timespec ts;
	add_ms_to_timespec(&ts, msec);
	SAFE_MUTEX_LOCK_R(mutex, n);
	SAFE_COND_TIMEDWAIT_R(cond, mutex, &ts, n); // sleep on sleep_cond
	SAFE_MUTEX_UNLOCK_R(mutex, n);
}

void cs_pthread_cond_init(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond)
{
	SAFE_MUTEX_INIT_R(mutex, NULL, n);
	__cs_pthread_cond_init(n, cond);
}

void cs_pthread_cond_init_nolog(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond)
{
	SAFE_MUTEX_INIT_NOLOG_R(mutex, NULL, n);
	__cs_pthread_cond_init(n, cond);
}

/* Return real time clock value calculated based on cs_gettime(). Use this instead of time() */
time_t cs_time(void)
{
	struct timeb tb;
	cs_ftime(&tb);
	return tb.time;
}

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

void cs_gettime(struct timespec *ts)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
#if defined(CLOCKFIX)
	if (tv.tv_sec > lasttime.tv_sec || (tv.tv_sec == lasttime.tv_sec && tv.tv_usec >= lasttime.tv_usec)) // check for time issues!
	{
		lasttime = tv; // register this valid time
	}
	else
	{
		tv = lasttime;
		settimeofday(&tv, NULL); // set time back to last known valid time
		//fprintf(stderr, "*** WARNING: BAD TIME AFFECTING WHOLE NCAM ECM HANDLING, SYSTEMTIME SET TO LAST KNOWN VALID TIME **** \n");
	}
#endif
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
	return;
}
