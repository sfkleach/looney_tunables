#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include "dl-tunables.h"


static bool
fetch_tunable(char * tunables, char **ename, char **evalue, char **next_tunables) {
    char *current_binding = tunables;
    *ename = NULL;
    *evalue = NULL;
    *next_tunables = NULL;
    for(;;) {
        if (current_binding[0] == '\0')
            return false;

        char * name = current_binding;
        size_t current_name_len = 0;
        while (name[current_name_len] != '=' && name[current_name_len] != ':' && name[current_name_len] != '\0') {
            current_name_len++;
        }

        /* If we reach the end of the string before getting a valid name-value pair, bail out.  */
        if (name[current_name_len] == '\0')
            return false;

        if (name[current_name_len] == ':') {
            /* We did not find a valid name-value pair before encountering the colon. */
            current_binding += current_name_len + 1;
            continue;
        }

        char * value = current_binding + current_name_len + 1;
        size_t current_value_len = 0;
        while (value[current_value_len] != ':' && value[current_value_len] != '\0') {
            current_value_len++;
        }

        /* Nul-terminate both strings. */
        name[current_name_len] = '\0';
        value[current_value_len] = '\0';

        *ename = name;
        *evalue = value;
        *next_tunables = current_binding + current_name_len + 1 + current_value_len;
        if (**next_tunables != '\0') {
            *next_tunables += 1;
        }

        return true;
    }
}

static tunable_t *
find_tunable(char *name) {
    for (size_t i = 0; i < sizeof(tunable_list) / sizeof(tunable_t); i++) {
        tunable_t *cur = &tunable_list[i];
        if (strcmp(cur->name, name) == 0) {
            return cur;
        }
    }
    return NULL;
}

static void
putchar_tuneable(char *sanitized_tunables, size_t *sanitized_end, char ch) {
    sanitized_tunables[*sanitized_end] = ch;
    *sanitized_end = *sanitized_end + 1;
}

static void
write_tunable(char *sanitized_tunables, size_t *sanitized_end, char *name, char *value) {
    if (*sanitized_end > 0) {
        putchar_tuneable(sanitized_tunables, sanitized_end, ':');
    }
    while (*name != '\0') {
        putchar_tuneable(sanitized_tunables, sanitized_end, *name++);
    }
    putchar_tuneable(sanitized_tunables, sanitized_end, ':');
    while (*value != '\0') {
        putchar_tuneable(sanitized_tunables, sanitized_end, *value++);
    }
}

static void
parse_tunables(char *sanitized_tunables, char *original_tunables)
{
    char * current_tunables = original_tunables;
    size_t sanitized_end = 0;

    char *name;
    char *value;
    char *next_tunables;
    while (fetch_tunable(current_tunables, &name, &value, &next_tunables)) {
        tunable_t *cur = find_tunable(name);
        if (cur != NULL) {
            if (__libc_enable_secure) {
                if (cur->security_level != TUNABLE_SECLEVEL_SXID_ERASE) {
                    write_tunable(sanitized_tunables, &sanitized_end, name, value);
                }
                if (cur->security_level != TUNABLE_SECLEVEL_NONE) {
                    tunable_initialize(cur, value);
                }
            } else {
                tunable_initialize(cur, value);
            }
        }

        current_tunables = next_tunables;
    }

    if (__libc_enable_secure) {
        sanitized_tunables[sanitized_end] = '\0';
    }
}
