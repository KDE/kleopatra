// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-License-Identifier: GPL-2.0-or-later

#include "keyexportdraghandler.h"

#include <kleopatraapplication.h>

#include "kleopatra_debug.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyList>

#include <QGpgME/ExportJob>
#include <QGpgME/Protocol>

#include <gpgme++/key.h>

// needed for GPGME_VERSION_NUMBER
#include <gpgme.h>

#include <QApplication>
#include <QFileInfo>
#include <QRegularExpression>
#include <QTemporaryDir>
#include <QUrl>

#include <KFileUtils>
#include <KLocalizedString>
#include <KMessageBox>

using namespace GpgME;
using namespace Kleo;

static QStringList supportedMimeTypes = {
    QStringLiteral("text/uri-list"),
    QStringLiteral("application/pgp-keys"),
    QStringLiteral("text/plain"),
};

class KeyExportMimeData : public QMimeData
{
    // cached data
    mutable QByteArray pgpData;
    mutable QByteArray smimeData;
    mutable QUrl tempFileUrl;

public:
    QVariant retrieveData(const QString &mimeType, QMetaType type) const override
    {
        Q_UNUSED(type);

#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
        if (pgpData.isEmpty() && !pgpFprs.isEmpty()) {
            auto job = QGpgME::openpgp()->publicKeyExportJob(true);
            job->exec(pgpFprs, pgpData);
        }
        if (smimeData.isEmpty() && !smimeFprs.isEmpty()) {
            auto job = QGpgME::smime()->publicKeyExportJob(true);
            job->exec(smimeFprs, smimeData);
        }
#endif

        if (mimeType == QLatin1StringView("text/uri-list")) {
            if (tempFileUrl.isEmpty()) {
                auto tempDirWeak = KleopatraApplication::instance()->createTemporaryDirectory();
                if (auto tempDir = tempDirWeak.lock()) {
                    QFile file{tempDir->filePath(fileName)};
                    if (file.open(QFile::NewOnly)) {
                        file.write(pgpData + smimeData);
                        file.close();
                        qCDebug(KLEOPATRA_LOG) << "Wrote file" << file.fileName();
                        tempFileUrl = QUrl(QStringLiteral("file://%1").arg(file.fileName()));
                    } else {
                        KMessageBox::error(nullptr, xi18nc("@info", "Failed to write the certificates to a temporary file."));
                        return {};
                    }
                } else {
                    KMessageBox::error(nullptr, xi18nc("@info", "Failed to write the certificates to a temporary file."));
                    return {};
                }
            }
            return tempFileUrl;
        } else if (mimeType == QLatin1StringView("application/pgp-keys")) {
            return pgpData;
        } else if (mimeType == QLatin1StringView("text/plain")) {
            QByteArray data = pgpData + smimeData;
            return data;
        }

        return {};
    }
    bool hasFormat(const QString &mimeType) const override
    {
        return supportedMimeTypes.contains(mimeType);
    }
    QStringList formats() const override
    {
        return supportedMimeTypes;
    }

    QStringList pgpFprs;
    QStringList smimeFprs;
    QString fileName;
};

KeyExportDragHandler::KeyExportDragHandler()
{
}

QStringList KeyExportDragHandler::mimeTypes() const
{
    return supportedMimeTypes;
}

Qt::ItemFlags KeyExportDragHandler::flags(const QModelIndex &index) const
{
    Q_UNUSED(index);
    return Qt::ItemIsDragEnabled | Qt::ItemIsSelectable | Qt::ItemIsEnabled;
}

QMimeData *KeyExportDragHandler::mimeData(const QModelIndexList &indexes) const
{
    auto mimeData = new KeyExportMimeData();

    QSet<QString> pgpFprs;
    QSet<QString> smimeFprs;

    // apparently we're getting an index for each column even though we're selecting whole rows
    // so figure out whether we're actually selecting more than one row
    bool singleRow = true;
    int row = indexes[0].row();
    auto parent = indexes[0].parent();

    for (const auto &index : indexes) {
        auto key = index.data(KeyList::KeyRole).value<Key>();

        (key.protocol() == GpgME::OpenPGP ? pgpFprs : smimeFprs) += QString::fromLatin1(key.primaryFingerprint());

        if (index.row() != row || index.parent() != parent) {
            singleRow = false;
        }
    }

    if (singleRow) {
        auto key = indexes[0].data(KeyList::KeyRole).value<Key>();
        auto keyName = Formatting::prettyName(key);
        if (keyName.isEmpty()) {
            keyName = Formatting::prettyEMail(key);
        }
        mimeData->fileName = QStringLiteral("%1_%2_public.%3")
                                 .arg(keyName, Formatting::prettyKeyID(key.keyID()), pgpFprs.isEmpty() ? QStringLiteral("pem") : QStringLiteral("asc"));
    } else {
        mimeData->fileName =
            i18nc("A generic filename for exported certificates", "certificates.%1", pgpFprs.isEmpty() ? QStringLiteral("pem") : QStringLiteral("asc"));
    }
    mimeData->pgpFprs = QStringList(pgpFprs.begin(), pgpFprs.end());
    mimeData->smimeFprs = QStringList(smimeFprs.begin(), smimeFprs.end());
    return mimeData;
}
