/* registry.c - Registry routines
   SPDX-FileCopyrightText: 2005, 2007 g 10 Code GmbH

   This file is part of GpgEX.

   SPDX-License-Identifier: LGPL-2.1-or-later
*/

/* keep this in sync with svn://cvs.gnupg.org/gpgex/trunk/src/registry.c (last checked against rev. 32) */

#include <config-kleopatra.h>

#if 0 /* We don't have a config.h in ONLY_KLEO, fix if needed */
#if HAVE_CONFIG_H
#include <config.h>
#endif
#endif

#include <unistd.h>
#include <windows.h>

#include <shlobj.h>
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001a
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif
#ifndef CSIDL_FLAG_CREATE
#define CSIDL_FLAG_CREATE 0x8000
#endif

#include "gnupg-registry.h"

/* This is a helper function to load a Windows function from either of
   one DLLs. */
HRESULT
w32_shgetfolderpath(HWND a, int b, HANDLE c, DWORD d, LPSTR e)
{
    static int initialized;
    typedef HRESULT(WINAPI * SHGetFolderPathAType)(HWND, int, HANDLE, DWORD, LPSTR);
    static SHGetFolderPathAType func;

    if (!initialized) {
        static const char *dllnames[] = {"shell32.dll", "shfolder.dll", NULL};
        void *handle;
        int i;

        initialized = 1;

        for (i = 0, handle = NULL; !handle && dllnames[i]; i++) {
            handle = LoadLibraryA(dllnames[i]);
            if (handle) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
                func = (SHGetFolderPathAType)GetProcAddress(handle, "SHGetFolderPathA");
#pragma GCC diagnostic pop
                if (!func) {
                    FreeLibrary(handle);
                    handle = NULL;
                }
            }
        }
    }

    if (func) {
        return func(a, b, c, d, e);
    } else {
        return -1;
    }
}

/* Helper for read_w32_registry_string(). */
static HKEY get_root_key(const char *root)
{
    HKEY root_key;

    if (!root) {
        root_key = HKEY_CURRENT_USER;
    } else if (!strcmp(root, "HKEY_CLASSES_ROOT")) {
        root_key = HKEY_CLASSES_ROOT;
    } else if (!strcmp(root, "HKEY_CURRENT_USER")) {
        root_key = HKEY_CURRENT_USER;
    } else if (!strcmp(root, "HKEY_LOCAL_MACHINE")) {
        root_key = HKEY_LOCAL_MACHINE;
    } else if (!strcmp(root, "HKEY_USERS")) {
        root_key = HKEY_USERS;
    } else if (!strcmp(root, "HKEY_PERFORMANCE_DATA")) {
        root_key = HKEY_PERFORMANCE_DATA;
    } else if (!strcmp(root, "HKEY_CURRENT_CONFIG")) {
        root_key = HKEY_CURRENT_CONFIG;
    } else {
        return NULL;
    }
    return root_key;
}

/* Return a string from the Win32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn.  */
char *read_w32_registry_string(const char *root, const char *dir, const char *name)
{
    HKEY root_key, key_handle;
    DWORD n1, nbytes, type;
    char *result = NULL;

    if (!(root_key = get_root_key(root))) {
        return NULL;
    }

    if (RegOpenKeyExA(root_key, dir, 0, KEY_READ, &key_handle)) {
        if (root) {
            return NULL; /* no need for a RegClose, so return direct */
        }
        /* It seems to be common practice to fall back to HKLM. */
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle)) {
            return NULL; /* still no need for a RegClose, so return direct */
        }
    }

    nbytes = 1;
    if (RegQueryValueExA(key_handle, name, 0, NULL, NULL, &nbytes)) {
        if (root) {
            goto leave;
        }
        /* Try to fallback to HKLM also vor a missing value.  */
        RegCloseKey(key_handle);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle)) {
            return NULL; /* Nope.  */
        }
        if (RegQueryValueExA(key_handle, name, 0, NULL, NULL, &nbytes)) {
            goto leave;
        }
    }
    result = malloc((n1 = nbytes + 1));
    if (!result) {
        goto leave;
    }
    if (RegQueryValueExA(key_handle, name, 0, &type, result, &n1)) {
        free(result);
        result = NULL;
        goto leave;
    }
    result[nbytes] = 0; /* make sure it is really a string  */
    if (type == REG_EXPAND_SZ && strchr(result, '%')) {
        char *tmp;

        n1 += 1000;
        tmp = malloc(n1 + 1);
        if (!tmp) {
            goto leave;
        }
        nbytes = ExpandEnvironmentStringsA(result, tmp, n1);
        if (nbytes && nbytes > n1) {
            free(tmp);
            n1 = nbytes;
            tmp = malloc(n1 + 1);
            if (!tmp) {
                goto leave;
            }
            nbytes = ExpandEnvironmentStringsA(result, tmp, n1);
            if (nbytes && nbytes > n1) {
                free(tmp); /* oops - truncated, better don't expand at all */
                goto leave;
            }
            tmp[nbytes] = 0;
            free(result);
            result = tmp;
        } else if (nbytes) { /* okay, reduce the length */
            tmp[nbytes] = 0;
            free(result);
            result = malloc(strlen(tmp) + 1);
            if (!result) {
                result = tmp;
            } else {
                strcpy(result, tmp);
                free(tmp);
            }
        } else { /* error - don't expand */
            free(tmp);
        }
    }

leave:
    RegCloseKey(key_handle);
    return result;
}
