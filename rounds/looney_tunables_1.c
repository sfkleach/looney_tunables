#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include "dl-tunables.h"

static void
parse_tunables(char *tunestr, char *valstring)
{
    // ... code removed for clarity.
    char *p = tunestr;
    size_t off = 0;

    while (true) {
        char *name = p;
        size_t len = 0;

        /* First, find where the name ends.  */
        while (p[len] != '=' && p[len] != ':' && p[len] != '\0') {
            len++;
        }

        /* If we reach the end of the string before getting a valid name-value
           pair, bail out.  */
        if (p[len] == '\0') {
            if (__libc_enable_secure) {
                tunestr[off] = '\0';
            }
            return;
        }

        /* We did not find a valid name-value pair before encountering the
           colon.  */
        if (p[len] == ':') {
            p += len + 1;
            continue;
        }

        p += len + 1;

        /* Take the value from the valstring since we need to NULL terminate it.  */
        char *value = &valstring[p - tunestr];
        len = 0;

        while (p[len] != ':' && p[len] != '\0') {
            len++;
        }

        /* Add the tunable if it exists.  */
        for (size_t i = 0; i < sizeof(tunable_list) / sizeof(tunable_t); i++) {
            tunable_t *cur = &tunable_list[i];

            if (tunable_is_name(cur->name, name)) {

                if (__libc_enable_secure) {
                    if (cur->security_level != TUNABLE_SECLEVEL_SXID_ERASE) {
                        if (off > 0) {
                            tunestr[off++] = ':';
                        }

                        const char *n = cur->name;

                        while (*n != '\0') {
                            tunestr[off++] = *n++;
                        }

                        tunestr[off++] = '=';

                        for (size_t j = 0; j < len; j++) {
                            tunestr[off++] = value[j];
                        }
                    }

                    if (cur->security_level != TUNABLE_SECLEVEL_NONE) {
                        break;
                    }
                }

                value[len] = '\0';
                tunable_initialize(cur, value);
                break;
            }
        }

        if (p[len] != '\0') {
            p += len + 1;
        }
    }
}
