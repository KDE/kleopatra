/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "csrutils.h"

#include "filedialog.h"

#include <utils/keyparameters.h>

#include <kleopatra_debug.h>

#include <Libkleo/KeyUsage>

#include <KLocalizedString>
#include <KMessageBox>

#include <QDate>
#include <QFile>
#include <QUrl>

#include <utils/qt6compat.h>

using namespace Kleo;
using namespace Qt::Literals;

namespace
{
struct SaveToFileResult {
    QString filename;
    QString errorMessage;
};

static SaveToFileResult saveRequestToFile(const QString &filename, const QByteArray &request, QIODevice::OpenMode mode)
{
    QFile file(filename);
    if (!file.open(mode)) {
        return {{}, file.errorString()};
    }
    const auto bytesWritten = file.write(request);
    if (bytesWritten < request.size()) {
        return {{}, file.errorString()};
    }
    return {file.fileName(), {}};
}
}

static QString usageText(KeyUsage usage)
{
    if (usage.canEncrypt()) {
        return usage.canSign() ? u"sign_encrypt"_s : u"encrypt"_s;
    }
    return u"sign"_s;
}

void Kleo::saveCSR(const QByteArray &request, const KeyParameters &keyParameters, QWidget *parent)
{
    const QString proposedFilename =
        u"request_%1_%2_%3.p10"_s.arg(usageText(keyParameters.keyUsage()), keyParameters.emails().front(), QDate::currentDate().toString(Qt::ISODate));

    SaveToFileResult result;
    while (result.filename.isEmpty()) {
        const QString filePath = FileDialog::getSaveFileNameEx(parent,
                                                               i18nc("@title", "Save Request"),
                                                               QStringLiteral("save_csr"),
                                                               proposedFilename,
                                                               i18n("PKCS#10 Requests (*.p10)"));
        if (filePath.isEmpty()) {
            // user canceled the dialog
            return;
        }
        result = saveRequestToFile(filePath, request, QIODevice::WriteOnly);
        if (result.filename.isEmpty()) {
            qCDebug(KLEOPATRA_LOG) << "Writing request to file" << filePath << "failed:" << result.errorMessage;
            KMessageBox::error(parent,
                               xi18nc("@info",
                                      "<para>Failed to write the request to the file <filename>%1</filename>.</para>"
                                      "<para><message>%2</message></para>",
                                      filePath,
                                      result.errorMessage));
        }
    }
    KMessageBox::information(parent,
                             xi18nc("@info",
                                    "<para>Successfully wrote request to <filename>%1</filename>.</para>"
                                    "<para>You should now send the request to the Certification Authority (CA).</para>",
                                    result.filename),
                             i18nc("@title:window", "Success"));
}
