#define MODULE_LOG_PREFIX "sched"  // Logging prefix for all scheduler messages

#include "globals.h"
#include "ncam-sched.h"
#include "ncam-string.h"
#include "ncam-time.h"
#include "ncam-net.h"
#include "ncam-lock.h"
#include "cscrypt/md5.h"

extern char cs_confdir[128];

#define MAX_JOBS        128     // Maximum number of concurrent jobs
#define MAX_STEPS       256     // Maximum steps per job (prevents infinite loops)
#define MAX_NAME        128     // Maximum job name length
#define MAX_QUERY       8192    // Maximum HTTP API query length
#define MAX_MSG         512     // Maximum log message length

typedef enum {
    API_OK = 0,     // Operation completed successfully
    API_ERR = -1    // Operation failed (network, auth, or server error)
} api_result_t;

/*
 * Job State Machine Enumeration
 * Tracks job lifecycle from scheduling through completion
 */
typedef enum {
    JOB_IDLE,      // Initial state: waiting for next scheduled trigger time
    JOB_READY,     // Trigger condition met: ready for thread execution
    JOB_RUNNING,   // Currently executing in worker thread
    JOB_DONE       // Execution completed (terminal state for non-recurring jobs)
} job_state_t;

/*
 * Step Type Enumeration
 * Defines available action types within job workflows
 */
typedef enum {
    STEP_API,      // Execute NCam API HTTP call
    STEP_LOG,      // Write entry to system log
    STEP_SLEEP     // Pause execution for specified duration
} step_type_t;

/*
 * Job Step Structure
 * Represents individual action within job execution sequence
 */
typedef struct {
    step_type_t type;      // Type of step (determines which union member is active)
    union {                // Step-specific data payload
        char api_query[MAX_QUERY];  // HTTP API endpoint and parameters
        char log_msg[MAX_MSG];      // Formatted log message text
        int sleep_sec;              // Sleep duration in seconds
    } data;
} job_step_t;

/*
 * Job Definition Structure
 * Complete configuration and runtime state for a scheduled task
 */
typedef struct {
    char name[MAX_NAME];           // Unique job identifier for logging
    int enabled;                   // Activation flag (0=disabled, 1=enabled)
    int loop;                      // Continuous execution mode (1=enabled)
    int interval_sec;              // Fixed interval between executions (seconds)
    
    // Daily scheduling parameters
    int hour, minute;              // Time of day for execution (24h format)
    
    // Weekly scheduling parameters  
    int weekday;                   // Day of week (0=Sunday, 6=Saturday)
    
    // Schedule type flags (mutually exclusive)
    int has_daily;                 // Daily schedule enabled
    int has_weekly;                // Weekly schedule enabled
    int has_datetime;              // One-time absolute schedule enabled
    
    time_t datetime_target;        // Absolute execution timestamp for one-time jobs
    
    // Step configuration
    job_step_t *steps;             // Dynamic array of job steps
    int step_count;                // Number of configured steps
    
    // Runtime statistics
    int run_count;                 // Total executions completed
    time_t next_run;               // Next scheduled execution time
    time_t last_run;               // Last execution completion time
    
    // State management
    job_state_t state;             // Current state in job lifecycle
    pthread_t thread;              // Worker thread handle
    volatile int is_running;       // Thread-safe execution flag
} job_t;

/*
 * Scheduler Context Structure
 * Global container for all scheduler state and control variables
 */
typedef struct {
    job_t jobs[MAX_JOBS];          // Fixed array of job definitions
    int job_count;                 // Active job count
    pthread_t thread;              // Main scheduler thread handle
    CS_MUTEX_LOCK lock;            // Mutex for thread-safe job access
    volatile int running;          // Global scheduler run flag
} sched_ctx_t;

/*
 * Global Scheduler Instance
 * Singleton instance containing all scheduler state
 */
static sched_ctx_t g_sched = {0};

// ============================================================================
// HTTP DIGEST AUTHENTICATION SUBSYSTEM
// ============================================================================

/*
 * HTTP Digest Authentication Extraction Helper
 * Purpose: Extracts quoted parameter values from HTTP WWW-Authenticate header
 * Process: Searches for "param="value"" pattern and copies value to output buffer
 * Security: Uses bounded copying to prevent buffer overflow
 */
#ifdef WEBIF
static int http_extract_quoted(const char *hdr, const char *param, char *out, size_t len)
{
    char search[64];                                       // Buffer for search pattern
    snprintf(search, sizeof(search), "%s=\"", param);      // Build "param=" pattern
    
    const char *start = strstr(hdr, search);               // Locate parameter start
    if (!start) return 0;                                  // Parameter not found
    
    start += cs_strlen(search);                            // Skip to value start
    const char *end = strchr(start, '"');                  // Find closing quote
    if (!end) return 0;                                    // Malformed header
    
    size_t n = end - start;                                // Calculate value length
    if (n >= len) n = len - 1;                             // Enforce buffer limit
    memcpy(out, start, n);                                 // Copy value
    out[n] = '\0';                                         // Null-terminate
    return 1;                                              // Success
}

/*
 * MD5 Hexadecimal Conversion
 * Purpose: Converts 16-byte MD5 hash to 32-character hexadecimal string
 * Process: Iterates through hash bytes, formatting each as two hex characters
 * Output: Null-terminated hex string (requires 33-byte buffer)
 */
static void digest_md5_hex(const unsigned char *md5, char *hex)
{
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)           // Process each hash byte
        snprintf(hex + (i * 2), 3, "%02x", md5[i]);       // Convert byte to hex
}

/*
 * HTTP Digest Authentication Header Generator
 * Purpose: Creates RFC 2617 compliant Digest Authentication header
 * Algorithm: response = MD5(MD5(username:realm:password):nonce:MD5(method:uri))
 * Security: Uses server-provided nonce, supports qop=auth for replay protection
 */
static int http_digest_auth(const char *user, const char *pass, const char *uri,
                            const char *realm, const char *nonce, const char *qop,
                            const char *opaque, char *out, size_t out_sz)
{
    // Step 1: Calculate HA1 = MD5(username:realm:password)
    char ha1_in[512];
    snprintf(ha1_in, sizeof(ha1_in), "%s:%s:%s", user, realm, pass ? pass : "");
    
    unsigned char ha1_md5[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)ha1_in, cs_strlen(ha1_in), ha1_md5);
    
    char ha1[33];
    digest_md5_hex(ha1_md5, ha1);
    
    // Step 2: Calculate HA2 = MD5(method:uri)
    char ha2_in[MAX_QUERY + 8];
    snprintf(ha2_in, sizeof(ha2_in), "GET:%s", uri);
    
    unsigned char ha2_md5[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)ha2_in, cs_strlen(ha2_in), ha2_md5);
    
    char ha2[33];
    digest_md5_hex(ha2_md5, ha2);
    
    // Step 3: Generate client nonce (timestamp-based)
    char cnonce[32];
    snprintf(cnonce, sizeof(cnonce), "%08lx", (unsigned long)cs_time());
    
    // Step 4: Calculate response based on qop presence
    char resp_in[1024];
    if (qop && qop[0]) {                                  // qop=auth enabled
        snprintf(resp_in, sizeof(resp_in), "%s:%s:00000001:%s:auth:%s", 
                ha1, nonce, cnonce, ha2);
    } else {                                              // Legacy qop-less
        snprintf(resp_in, sizeof(resp_in), "%s:%s:%s", ha1, nonce, ha2);
    }
    
    // Step 5: Final response hash
    unsigned char resp_md5[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)resp_in, cs_strlen(resp_in), resp_md5);
    
    char response[33];
    digest_md5_hex(resp_md5, response);
    
    // Step 6: Format complete Authorization header
    if (qop && qop[0]) {                                  // Modern with qop
        if (opaque && opaque[0]) {                        // Include opaque if provided
            snprintf(out, out_sz,
                "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                "uri=\"%s\", qop=auth, nc=00000001, cnonce=\"%s\", "
                "response=\"%s\", opaque=\"%s\"",
                user, realm, nonce, uri, cnonce, response, opaque);
        } else {                                          // Without opaque
            snprintf(out, out_sz,
                "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                "uri=\"%s\", qop=auth, nc=00000001, cnonce=\"%s\", response=\"%s\"",
                user, realm, nonce, uri, cnonce, response);
        }
    } else {                                              // Legacy without qop
        snprintf(out, out_sz,
            "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
            "uri=\"%s\", response=\"%s\"",
            user, realm, nonce, uri, response);
    }
    
    return 1;                                             // Success
}

/*
 * HTTP Status Code Extractor
 * Purpose: Parses HTTP response line to extract numeric status code
 * Process: Locates "HTTP/" prefix, finds first space, converts following number
 * Returns: Integer status code, 0 if malformed response
 */
static int http_get_status(const char *resp)
{
    if (!resp) return 0;                                  // Null check
    const char *http = strstr(resp, "HTTP/");            // Find protocol start
    if (!http) return 0;                                  // Not HTTP response
    const char *space = strchr(http, ' ');                // Locate status separator
    return space ? atoi(space + 1) : 0;                  // Convert to integer
}

/*
 * HTTP Request Execution
 * Purpose: Performs TCP HTTP request to local NCam web interface
 * Process: Creates socket, connects to localhost, sends GET, receives response
 * Security: Uses TCP_NODELAY for performance, configurable timeouts
 */
static int http_request(int port, const char *uri, const char *auth, 
                        char *resp, size_t resp_sz)
{
    // Step 1: Configure socket address (localhost)
    struct SOCKADDR sad;
    memset(&sad, 0, sizeof(sad));                        // Clear structure
    SIN_GET_FAMILY(sad) = DEFAULT_AF;                    // IPv4/IPv6 based on config
    set_localhost_ip(&SIN_GET_ADDR(sad));                // Set to 127.0.0.1
    SIN_GET_PORT(sad) = htons(port);                     // Convert port to network order
    
    // Step 2: Create TCP socket
    int sock = socket(DEFAULT_AF, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return -1;                             // Socket creation failed
    
    // Step 3: Configure socket options
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)); // Disable Nagle
    setTCPTimeouts(sock);                                 // Apply NCam timeout defaults
    
    // Step 4: Establish connection
    if (connect(sock, (struct sockaddr *)&sad, sizeof(sad)) < 0) {
        close(sock);                                     // Cleanup on failure
        return -1;
    }
    
    // Step 5: Build HTTP GET request
    char req[32768];
    int len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "%s%s%s"
        "Connection: close\r\n\r\n",
        uri, port,
        auth ? "Authorization: " : "",                   // Conditional auth header
        auth ? auth : "",
        auth ? "\r\n" : "");
    
    // Step 6: Validate request length
    if (len < 0 || (size_t)len >= sizeof(req)) {
        close(sock);
        return -1;
    }
    
    // Step 7: Send request
    if (send(sock, req, len, 0) < 0) {
        close(sock);
        return -1;
    }
    
    // Step 8: Receive response
    ssize_t received = recv(sock, resp, resp_sz - 1, 0);
    close(sock);                                         // Always close socket
    
    if (received <= 0) return -1;                       // Receive failed
    resp[received] = '\0';                               // Null-terminate
    
    return http_get_status(resp);                        // Return HTTP status
}

/*
 * Public API Call Interface
 * Purpose: Main entry point for job steps to execute NCam API calls
 * Process: Attempts unauthenticated request, handles 401 with Digest auth if needed
 * Security: Validates credentials before use, logs all failures
 */
api_result_t ncam_api_call(const char *query)
{
    // Step 1: Input validation
    if (!query || !*query) return API_ERR;              // Empty query
    
    // Step 2: Determine HTTP port
    int port = cfg.http_port > 0 ? cfg.http_port : 8181; // Default to 8181
    
    // Step 3: Build URI from query
    char uri[MAX_QUERY];
    snprintf(uri, sizeof(uri), "/%s", query);           // Add leading slash
    
    // Step 4: Check if authentication required
    int need_auth = (cfg.http_user && cfg.http_user[0]);
    char resp[8192];
    
    // Step 5: Initial unauthenticated attempt
    int code = http_request(port, uri, NULL, resp, sizeof(resp));
    
    if (code < 0) {                                      // Network/connection error
        cs_log("API: Connection failed to 127.0.0.1:%d", port);
        return API_ERR;
    }
    
    // Step 6: Handle 401 Unauthorized with Digest auth
    if (code == 401 && need_auth) {
        char realm[256] = {0}, nonce[256] = {0};
        char qop[64] = {0}, opaque[256] = {0};
        
        // Extract authentication parameters from WWW-Authenticate header
        if (http_extract_quoted(resp, "realm", realm, sizeof(realm)) &&
            http_extract_quoted(resp, "nonce", nonce, sizeof(nonce))) {
            
            http_extract_quoted(resp, "qop", qop, sizeof(qop));
            http_extract_quoted(resp, "opaque", opaque, sizeof(opaque));
            
            // Generate Digest authentication header
            char auth[16384];
            if (!http_digest_auth(cfg.http_user, 
                                  cfg.http_pwd ? cfg.http_pwd : "",
                                  uri, realm, nonce, qop, opaque, 
                                  auth, sizeof(auth))) {
                return API_ERR;                         // Auth generation failed
            }
            
            // Retry request with authentication
            code = http_request(port, uri, auth, resp, sizeof(resp));
            if (code < 0) {                              // Auth request failed
                cs_log("API: Auth request failed");
                return API_ERR;
            }
        }
    }
    
    // Step 7: Evaluate response
    if (code >= 200 && code < 300) return API_OK;       // Success (2xx)
    
    if (code >= 400) {                                   // Client/Server error
        cs_log("API: HTTP %d for %s", code, query);
    }
    
    return API_ERR;                                      // Any other failure
}

#else // !WEBIF (Compilation without web interface)

/*
 * Stub API Function (WEBIF disabled)
 * Purpose: Provides null implementation when web interface is not compiled
 * Rationale: Allows scheduler to compile without HTTP support
 */
api_result_t ncam_api_call(const char *query) 
{ 
    (void)query;                                         // Suppress unused parameter
    return API_ERR;                                      // Always fail
}

#endif // WEBIF

/*
 * Daily Schedule Calculator
 * Purpose: Computes next execution timestamp for daily-recurring jobs
 * Process: Sets today's time to specified hour:minute, advances to tomorrow if passed
 * Returns: UNIX timestamp of next occurrence
 */
static time_t sched_calc_daily(int hour, int minute)
{
    time_t now = cs_time();                              // Current system time
    struct tm tm_now;
    localtime_r(&now, &tm_now);                          // Convert to local time struct
    
    tm_now.tm_hour = hour;                               // Override hour
    tm_now.tm_min = minute;                              // Override minute
    tm_now.tm_sec = 0;                                   // Start of minute
    tm_now.tm_isdst = -1;                                // Let system determine DST
    
    time_t target = mktime(&tm_now);                     // Convert back to timestamp
    if (target <= now) target += 86400;                  // Advance to next day if passed
    return target;                                       // Next execution time
}

/*
 * Weekly Schedule Calculator
 * Purpose: Computes next execution timestamp for weekly-recurring jobs
 * Process: Calculates days until target weekday, adjusts time, handles wrap-around
 * Returns: UNIX timestamp of next occurrence
 */
static time_t sched_calc_weekly(int weekday, int hour, int minute)
{
    time_t now = cs_time();                              // Current system time
    struct tm tm_now;
    localtime_r(&now, &tm_now);                          // Convert to local time
    
    int cur_wday = tm_now.tm_wday;                       // Current weekday (0=Sun)
    int days = (weekday - cur_wday + 7) % 7;             // Days until target weekday
    
    if (days == 0) {                                     // Today is target day
        tm_now.tm_hour = hour;                           // Set target hour
        tm_now.tm_min = minute;                          // Set target minute
        tm_now.tm_sec = 0;                               // Start of minute
        tm_now.tm_isdst = -1;                            // DST auto
        
        time_t target = mktime(&tm_now);                 // Today's target time
        if (target > now) return target;                 // If not passed, use today
        days = 7;                                        // Otherwise next week
    }
    
    // Calculate base for next week's occurrence
    time_t target = now + (days * 86400);                // Add days
    localtime_r(&target, &tm_now);                       // Convert for time setting
    
    tm_now.tm_hour = hour;                               // Set hour
    tm_now.tm_min = minute;                              // Set minute
    tm_now.tm_sec = 0;                                   // Start of minute
    tm_now.tm_isdst = -1;                                // DST auto
    
    return mktime(&tm_now);                              // Final timestamp
}

/*
 * Job Thread Entry Point
 * Purpose: Executes job steps sequentially in dedicated thread
 * Process: Iterates through steps, handles each type, updates job state on completion
 * Thread Safety: Uses mutex for state transitions, detaches on completion
 */
static void *sched_job_run(void *arg)
{
    job_t *job = (job_t *)arg;                           // Cast thread argument
    if (!job) return NULL;                               // Safety check
    
    // Step 1: Transition to RUNNING state (thread-safe)
    cs_writelock(__func__, &g_sched.lock);
    job->state = JOB_RUNNING;
    cs_writeunlock(__func__, &g_sched.lock);
    
    // Step 2: Execute each job step in sequence
    for (int i = 0; i < job->step_count; i++) {
        switch (job->steps[i].type) {
            case STEP_API:
                // Execute API call, log failure but continue execution
                if (ncam_api_call(job->steps[i].data.api_query) != API_OK) {
                    cs_log("[%s] API call failed at step %d", job->name, i + 1);
                }
                break;
                
            case STEP_LOG:
                // Write formatted message to system log
                cs_log("[%s] %s", job->name, job->steps[i].data.log_msg);
                break;
                
            case STEP_SLEEP:
                // Pause execution for specified duration
                if (job->steps[i].data.sleep_sec > 0) {
                    sleep(job->steps[i].data.sleep_sec);
                }
                break;
        }
    }
    
    // Step 3: Post-execution processing
    time_t now = cs_time();                              // Capture completion time
    
    // Step 4: Update job state (thread-safe)
    cs_writelock(__func__, &g_sched.lock);
    job->is_running = 0;                                 // Clear running flag
    job->last_run = now;                                 // Record completion time
    job->run_count++;                                    // Increment execution counter
    
    // Step 5: Determine next state based on schedule type
    if (job->has_datetime) {                             // One-time job
        job->state = JOB_DONE;                           // Terminal state
        job->enabled = 0;                                // Disable future execution
    }
    else if (job->loop) {                                // Continuous loop mode
        job->state = JOB_IDLE;
        // Use interval or minimum 1 second
        job->next_run = now + (job->interval_sec > 0 ? job->interval_sec : 1);
    }
    else if (job->interval_sec > 0) {                    // Fixed interval
        job->state = JOB_IDLE;
        job->next_run = now + job->interval_sec;
    }
    else if (job->has_daily) {                           // Daily schedule
        job->state = JOB_IDLE;
        job->next_run = sched_calc_daily(job->hour, job->minute);
    }
    else if (job->has_weekly) {                          // Weekly schedule
        job->state = JOB_IDLE;
        job->next_run = sched_calc_weekly(job->weekday, job->hour, job->minute);
    }
    else {                                               // Invalid configuration
        job->state = JOB_DONE;                           // Terminal state
        job->enabled = 0;                                // Disable
    }
    
    cs_writeunlock(__func__, &g_sched.lock);
    return NULL;                                         // Thread exit
}

/*
 * Main Scheduler Loop
 * Purpose: Monitors all jobs, triggers execution when scheduled
 * Process: Polls job states every 200ms, spawns threads for ready jobs
 * Thread: Runs continuously until shutdown signal received
 */
static void *sched_loop(void *UNUSED(arg))
{
    while (g_sched.running) {                            // Continue until shutdown
        time_t now = cs_time();                          // Current timestamp
        
        // Thread-safe job processing
        cs_writelock(__func__, &g_sched.lock);
        for (int i = 0; i < g_sched.job_count; i++) {
            job_t *job = &g_sched.jobs[i];
            
            // Skip conditions
            if (!job->enabled || job->is_running || job->step_count == 0)
                continue;
                
            // Check if job should transition to READY state
            if (job->state == JOB_IDLE && job->next_run <= now) {
                job->state = JOB_READY;
            }
            
            // Launch job thread if ready and not already running
            if (job->state == JOB_READY && !job->is_running) {
                job->is_running = 1;                     // Set running flag
                if (pthread_create(&job->thread, NULL, sched_job_run, job) != 0) {
                    job->is_running = 0;                 // Reset on failure
                    cs_log("[%s] Failed to create thread", job->name);
                } else {
                    pthread_detach(job->thread);         // Auto-cleanup on completion
                }
            }
        }
        cs_writeunlock(__func__, &g_sched.lock);
        
        usleep(200000);                                  // Poll every 200ms
    }
    return NULL;                                         // Shutdown complete
}

/*
 * Configuration File Parser
 * Purpose: Loads job definitions from task.cfg file
 * Process: Line-by-line parsing with section and key-value support
 * Validation: Enforces limits, validates formats, logs loaded configuration
 */
static int sched_load_cfg(FILE *fp)
{
    if (!fp) return -1;                                  // Null file pointer

    // Initialize scheduler context
    g_sched.job_count = 0;
    char line[512];
    job_t *cur = NULL;                                   // Current job being parsed

    // Process each configuration line
    while (fgets(line, sizeof(line), fp)) {
        trim(line);                                      // Remove whitespace
        if (*line == '\0' || *line == '#') continue;     // Skip empty/comments

        // Detect job section header: [job:JobName]
        char name[MAX_NAME];
        if (sscanf(line, "[job:%127[^]]]", name) == 1) {
            if (g_sched.job_count >= MAX_JOBS) break;    // Capacity limit
            
            // Initialize new job entry
            cur = &g_sched.jobs[g_sched.job_count++];
            memset(cur, 0, sizeof(job_t));               // Clear all fields
            cs_strncpy(cur->name, name, MAX_NAME);       // Set job name

            // Default values
            cur->enabled = 1;
            cur->state = JOB_IDLE;
            cur->next_run = cs_time();                   // Default to immediate

            // Allocate steps array
            if (!cs_malloc(&cur->steps, MAX_STEPS * sizeof(job_step_t))) {
                g_sched.job_count--;                     // Rollback on allocation failure
                cur = NULL;
            }
            continue;
        }

        if (!cur) continue;                              // Skip if no active job

        // Parse key=value pairs
        char *eq = strchr(line, '=');
        if (!eq) continue;                               // Invalid format
        
        *eq = '\0';                                      // Split key and value
        char *key = line;
        char *val = eq + 1;
        trim(key);                                       // Clean key
        trim(val);                                       // Clean value
        if (!*val) continue;                             // Skip empty values

        // Process known configuration keys
        if (strcmp(key, "enabled") == 0) {
            cur->enabled = atoi(val);                    // Convert to integer
        }
        else if (strcmp(key, "loop") == 0) {
            cur->loop = atoi(val);                       // Loop mode
        }
        else if (strcmp(key, "interval") == 0) {
            cur->interval_sec = atoi(val);               // Fixed interval
        }
        else if (strcmp(key, "time") == 0) {             // Daily schedule
            if (sscanf(val, "%d:%d", &cur->hour, &cur->minute) == 2) {
                cur->has_daily = 1;
                cur->next_run = sched_calc_daily(cur->hour, cur->minute);
            }
        }
        else if (strcmp(key, "weekly") == 0) {           // Weekly schedule
            char day[16];
            if (sscanf(val, "%15s %d:%d", day, &cur->hour, &cur->minute) == 3) {
                cur->has_weekly = 1;
                // Convert day name to numeric weekday
                if (strcasecmp(day, "sunday") == 0 || strcasecmp(day, "sun") == 0) cur->weekday = 0;
                else if (strcasecmp(day, "monday") == 0 || strcasecmp(day, "mon") == 0) cur->weekday = 1;
                else if (strcasecmp(day, "tuesday") == 0 || strcasecmp(day, "tue") == 0) cur->weekday = 2;
                else if (strcasecmp(day, "wednesday") == 0 || strcasecmp(day, "wed") == 0) cur->weekday = 3;
                else if (strcasecmp(day, "thursday") == 0 || strcasecmp(day, "thu") == 0) cur->weekday = 4;
                else if (strcasecmp(day, "friday") == 0 || strcasecmp(day, "fri") == 0) cur->weekday = 5;
                else if (strcasecmp(day, "saturday") == 0 || strcasecmp(day, "sat") == 0) cur->weekday = 6;
                else cur->has_weekly = 0;                // Invalid day name

                if (cur->has_weekly) {
                    cur->next_run = sched_calc_weekly(cur->weekday, cur->hour, cur->minute);
                }
            }
        }
        else if (strcmp(key, "datetime") == 0) {         // One-time absolute
            struct tm tm = {0};
            if (sscanf(val, "%d-%d-%d %d:%d:%d",
                     &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                     &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
                tm.tm_year -= 1900;                      // Adjust for struct tm
                tm.tm_mon -= 1;                          // Month is 0-based
                cur->has_datetime = 1;
                cur->datetime_target = mktime(&tm);
                cur->next_run = cur->datetime_target;
            }
        }
        else if (strcmp(key, "api") == 0) {              // API call step
            if (cur->step_count < MAX_STEPS) {
                cur->steps[cur->step_count].type = STEP_API;
                cs_strncpy(cur->steps[cur->step_count].data.api_query, val, MAX_QUERY);
                cur->step_count++;
            }
        }
        else if (strcmp(key, "log") == 0) {              // Log step
            if (cur->step_count < MAX_STEPS) {
                cur->steps[cur->step_count].type = STEP_LOG;
                cs_strncpy(cur->steps[cur->step_count].data.log_msg, val, MAX_MSG);
                cur->step_count++;
            }
        }
        else if (strcmp(key, "sleep") == 0) {            // Sleep step
            int sec = atoi(val);
            if (cur->step_count < MAX_STEPS && sec > 0) {
                cur->steps[cur->step_count].type = STEP_SLEEP;
                cur->steps[cur->step_count].data.sleep_sec = sec;
                cur->step_count++;
            }
        }
    }

    // Log loaded configuration for debugging
    for (int i = 0; i < g_sched.job_count; i++) {
        job_t *j = &g_sched.jobs[i];
        cs_log("Loaded job '%s': steps=%d loop=%d interval=%d daily=%d weekly=%d datetime=%d", 
               j->name, j->step_count, j->loop, j->interval_sec, 
               j->has_daily, j->has_weekly, j->has_datetime);
    }
    
    cs_log("Loaded %d job(s)", g_sched.job_count);
    return 0;                                            // Success
}

/*
 * Scheduler Initialization
 * Purpose: Bootstrap scheduler subsystem
 * Process: Checks configuration, loads task.cfg, creates threads and locks
 * Returns: 0 on success, -1 on critical failure
 */
int32_t ncam_sched_init(void)
{
    // Feature check
    if (!cfg.task_enabled)
        return 0;                                        // Scheduler disabled

    // Construct configuration file path
    char task_path[256];
    snprintf(task_path, sizeof(task_path), "%stask.cfg", cs_confdir);

    // Open configuration file
    FILE *fp = fopen(task_path, "r");
    if (!fp) {
        cs_log("Task file not found: %s", task_path);
        return 0;                                        // Non-critical (optional feature)
    }

    // Initialize global scheduler context
    memset(&g_sched, 0, sizeof(sched_ctx_t));
    cs_lock_create(__func__, &g_sched.lock, "sched_lock", 5000);

    // Load configuration
    int ret = sched_load_cfg(fp);
    fclose(fp);                                          // Always close file

    // Validate loaded configuration
    if (ret != 0 || g_sched.job_count == 0) {
        cs_lock_destroy(__func__, &g_sched.lock);        // Cleanup
        return 0;                                        // No jobs to schedule
    }

    // Start main scheduler thread
    g_sched.running = 1;                                 // Set run flag
    if (pthread_create(&g_sched.thread, NULL, sched_loop, NULL) != 0) {
        g_sched.running = 0;                             // Reset on failure
        cs_lock_destroy(__func__, &g_sched.lock);        // Cleanup
        return -1;                                       // Critical failure
    }

    cs_log("Scheduler started with %d job(s)", g_sched.job_count);
    return 0;                                            // Success
}

/*
 * Scheduler Graceful Shutdown
 * Purpose: Cleanly terminate scheduler and all worker threads
 * Process: Signals stop, joins main thread, waits for workers, cleans resources
 * Safety: Ensures no resource leaks, waits for running jobs to complete
 */
void ncam_sched_shutdown(void)
{
    if (!g_sched.running) return;                       // Already stopped

    // Step 1: Signal main scheduler thread to stop
    g_sched.running = 0;
    pthread_join(g_sched.thread, NULL);                  // Wait for main thread

    // Step 2: Wait for worker threads to complete (max 10 seconds)
    for (int w = 0; w < 100; w++) {
        int running = 0;
        cs_writelock(__func__, &g_sched.lock);
        for (int i = 0; i < g_sched.job_count; i++)
            if (g_sched.jobs[i].is_running) running++;   // Count active workers
        cs_writeunlock(__func__, &g_sched.lock);

        if (!running) break;                             // All threads completed
        usleep(100000);                                  // Wait 100ms
    }

    // Step 3: Free allocated resources
    for (int i = 0; i < g_sched.job_count; i++)
        if (g_sched.jobs[i].steps)
            NULLFREE(g_sched.jobs[i].steps);             // Free step arrays

    // Step 4: Destroy synchronization primitives
    cs_lock_destroy(__func__, &g_sched.lock);
    cs_log("Scheduler stopped");                         // Final status
}
