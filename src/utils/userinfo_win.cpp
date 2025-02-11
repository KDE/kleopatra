/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "userinfo_win_p.h"

#include "kleopatra_debug.h"

/* Use Windows API to query the user name and email.
   EXTENDED_NAME_FORMAT is documented in MSDN */
QString win_get_user_name(EXTENDED_NAME_FORMAT what)
{
    QString ret;
    wchar_t tmp[1];
    ULONG nSize = 1;
    if (what == NameUnknown) {
        if (GetUserNameW(tmp, &nSize)) {
            qCWarning(KLEOPATRA_LOG) << "Got empty username";
            return ret;
        }
    } else if (GetUserNameExW(what, tmp, &nSize)) {
        return ret;
    }

    /* nSize now contains the required size of the buffer */
    wchar_t *buf = new wchar_t[nSize];

    if (what == NameUnknown) {
        if (!GetUserNameW(buf, &nSize)) {
            qCWarning(KLEOPATRA_LOG) << "Failed to get username";
            delete[] buf;
            return ret;
        }
    } else if (!GetUserNameExW(what, buf, &nSize)) {
        delete[] buf;
        return ret;
    }
    ret = QString::fromWCharArray(buf);
    delete[] buf;
    return ret.trimmed();
}

static bool has_high_integrity(HANDLE hToken)
{
    PTOKEN_MANDATORY_LABEL integrity_label = NULL;
    DWORD integrity_level = 0, size = 0;

    if (hToken == NULL || hToken == INVALID_HANDLE_VALUE) {
        qCWarning(KLEOPATRA_LOG) << "Invalid parameters.";
        return false;
    }

    /* Get the required size */
    if (GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        qCDebug(KLEOPATRA_LOG) << "Failed to get required size.";
        return false;
    }
    integrity_label = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, size);
    if (integrity_label == NULL) {
        qCDebug(KLEOPATRA_LOG) << "Failed to allocate label.";
        return false;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, integrity_label, size, &size)) {
        qCDebug(KLEOPATRA_LOG) << "Failed to get integrity level.";
        LocalFree(integrity_label);
        return false;
    }

    /* Get the last integrity level */
    integrity_level = *GetSidSubAuthority(integrity_label->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(integrity_label->Label.Sid) - 1));

    LocalFree(integrity_label);

    return integrity_level >= SECURITY_MANDATORY_HIGH_RID;
}

bool win_user_is_elevated()
{
    HANDLE hToken = NULL;
    bool ret = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD elevation;
        DWORD cbSize = sizeof(DWORD);
        /* First get the elevation token and then check if that
         * token has high integrity afterwards. */
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(TokenElevation), &cbSize)) {
            qCDebug(KLEOPATRA_LOG) << "Got ElevationToken " << elevation;
            ret = elevation;
        }
    }
    /* Elevation will be true and ElevationType TokenElevationTypeFull even
       if the token is a user token created by SAFER so we additionally
       check the integrity level of the token which will only be high in
       the real elevated process and medium otherwise. */

    ret = ret && has_high_integrity(hToken);

    if (hToken) {
        CloseHandle(hToken);
    }
    return ret;
}
