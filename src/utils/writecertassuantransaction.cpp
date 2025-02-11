/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "writecertassuantransaction.h"

#include <QByteArray>

#include <gpgme++/data.h>

#include <string.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace GpgME;

WriteCertAssuanTransaction::WriteCertAssuanTransaction(const QByteArray &certificateData)
    : DefaultAssuanTransaction()
    , mCertData(certificateData.constData(), certificateData.size())
{
}

WriteCertAssuanTransaction::~WriteCertAssuanTransaction()
{
}

namespace
{
static bool startsWithKeyword(const char *string, const char *keyword)
{
    // simplified version of has_leading_keyword() in gnupg/common/stringhelp.c
    if (!string || !keyword) {
        return false;
    }

    const size_t n = strlen(keyword);
    return !strncmp(string, keyword, n) && (!string[n] || string[n] == ' ' || string[n] == '\t');
}
}

Data WriteCertAssuanTransaction::inquire(const char *name, const char *args, Error &err)
{
    (void)args;
    (void)err;
    qCDebug(KLEOPATRA_LOG) << "WriteCertAssuanTransaction::inquire() - name:" << name;

    if (startsWithKeyword(name, "CERTDATA")) {
        return mCertData;
    } else {
        return Data::null;
    }
}
