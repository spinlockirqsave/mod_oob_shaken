#include <switch.h>
#include <g711.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>

#include <stir_shaken.h>


#ifdef WIN32
    #include <float.h>
    #define ISNAN(x) (!!(_isnan(x)))
    #define ISINF(x) (isinf(x))
#else
    int __isnan(double);
	int __isinf(double);
    #define ISNAN(x) (__isnan(x))
    #define ISINF(x) (__isinf(x))
#endif

#define oob_min(x, y) ((x) < (y) ? (x) : (y))
#define oob_max(x, y) ((x) < (y) ? (y) : (x))

typedef struct oob_session_s {
	switch_mutex_t				*mutex;
	switch_core_session_t		*fs_session;
	switch_media_bug_t			*bug;
	switch_channel_t			*channel;
} oob_session_t;
