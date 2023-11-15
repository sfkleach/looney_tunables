#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include "dl-tunables.h"

static void
parse_tunables(char *sanitized_tunables, char *original_tunables)
{
    /* ... code removed for clarity. */
    char *current_binding = sanitized_tunables;
    size_t sanitized_end = 0;

    while (current_binding[0] != '\0') {
        /* Loop invariants:
            - current_binding points to the start of the next unprocessed binding in sanitized_tunables.
            - sanitized_end <= (current_binding - sanitized_tunables).
            - all previous (valid) bindings have been copied to sanitized_tunables.
        */

        char *current_name = current_binding;
        size_t current_name_len = 0;

        /* First, find where the name ends.  */
        while (current_binding[current_name_len] != '=' && current_binding[current_name_len] != ':' && current_binding[current_name_len] != '\0') {
            current_name_len++;
        }

        /* If we reach the end of the string before getting a valid name-value
           pair, bail out.  */
        if (current_binding[current_name_len] == '\0')
            break;

        /* We did not find a valid name-value pair before encountering the
           colon. */
        if (current_binding[current_name_len] == ':') {
            current_binding += current_name_len + 1;
            continue;
        }

        char * current_value = current_binding + current_name_len + 1;
        size_t current_value_len = 0;
        while (current_value[current_value_len] != ':' && current_value[current_value_len] != '\0') {
            current_value_len++;
        }

        /* Take the value from the original_tunables since we will value need a NULL terminated value.  */
        char *value = &original_tunables[current_value - sanitized_tunables];
        /* Ensure null-termination. Note that original tuneables is persistent and can be updated for these purposes. */
        value[current_value_len] = '\0';

        /*  Add the tunable if it exists. Note that we do not use any data
            from santized_tunables, and do not write past the end of the next
            tunable pair.
        */
        for (size_t i = 0; i < sizeof(tunable_list) / sizeof(tunable_t); i++) {
            tunable_t *cur = &tunable_list[i];

            if (tunable_is_name(cur->name, current_name)) {

                if (__libc_enable_secure) {
                    if (cur->security_level != TUNABLE_SECLEVEL_SXID_ERASE) {
                        if (sanitized_end > 0) {
                            sanitized_tunables[sanitized_end++] = ':';
                        }

                        /* Note that cur->name is null terminated, so we can use it directly. */  
                        const char *n = cur->name;

                        while (*n != '\0') {
                            sanitized_tunables[sanitized_end++] = *n++;
                        }

                        sanitized_tunables[sanitized_end++] = '=';

                        for (size_t j = 0; j < current_name_len; j++) {
                            sanitized_tunables[sanitized_end++] = value[j];
                        }
                    }

                    if (cur->security_level != TUNABLE_SECLEVEL_NONE) {
                        break;
                    }
                }

                tunable_initialize(cur, value);
                break;
            }
        }

        /* Advance to the next binding. */
        size_t offset_to_separator = current_name_len + current_value_len + 1;
        if (current_binding[offset_to_separator] != '\0') {
            current_binding += offset_to_separator + 1;
        }
    }

    if (__libc_enable_secure) {
        sanitized_tunables[sanitized_end] = '\0';
    }
}
