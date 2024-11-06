/* -*- mode: c++; c-basic-offset:4 -*-
    importcertificatefromfilecommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "importcertificatefromfilecommand.h"
#include "importcertificatescommand_p.h"

#include <kleopatra_debug.h>

#include <QGpgME/Protocol>

#include <Libkleo/Classify>

#include <gpgme++/global.h>
#include <gpgme++/importresult.h>

#include <KConfigGroup>
#include <KLocalizedString>

#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QString>
#include <QStringDecoder>
#include <QWidget>

#include <KSharedConfig>

#include <memory>

using namespace GpgME;
using namespace Kleo;
using namespace QGpgME;

class ImportCertificateFromFileCommand::Private : public ImportCertificatesCommand::Private
{
    friend class ::ImportCertificateFromFileCommand;
    ImportCertificateFromFileCommand *q_func() const
    {
        return static_cast<ImportCertificateFromFileCommand *>(q);
    }

public:
    explicit Private(ImportCertificateFromFileCommand *qq, KeyListController *c);
    ~Private() override;

    bool ensureHaveFile();

private:
    QStringList files;
};

ImportCertificateFromFileCommand::Private *ImportCertificateFromFileCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ImportCertificateFromFileCommand::Private *ImportCertificateFromFileCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

ImportCertificateFromFileCommand::Private::Private(ImportCertificateFromFileCommand *qq, KeyListController *c)
    : ImportCertificatesCommand::Private(qq, c)
    , files()
{
}

ImportCertificateFromFileCommand::Private::~Private()
{
}

#define d d_func()
#define q q_func()

ImportCertificateFromFileCommand::ImportCertificateFromFileCommand()
    : ImportCertificatesCommand(new Private(this, nullptr))
{
}

ImportCertificateFromFileCommand::ImportCertificateFromFileCommand(KeyListController *p)
    : ImportCertificatesCommand(new Private(this, p))
{
}

ImportCertificateFromFileCommand::ImportCertificateFromFileCommand(QAbstractItemView *v, KeyListController *p)
    : ImportCertificatesCommand(v, new Private(this, p))
{
}

ImportCertificateFromFileCommand::ImportCertificateFromFileCommand(const QStringList &files, KeyListController *p)
    : ImportCertificatesCommand(new Private(this, p))
{
    d->files = files;
}

ImportCertificateFromFileCommand::ImportCertificateFromFileCommand(const QStringList &files, QAbstractItemView *v, KeyListController *p)
    : ImportCertificatesCommand(v, new Private(this, p))
{
    d->files = files;
}

ImportCertificateFromFileCommand::~ImportCertificateFromFileCommand()
{
}

void ImportCertificateFromFileCommand::setFiles(const QStringList &files)
{
    d->files = files;
}

void ImportCertificateFromFileCommand::doStart()
{
    if (!d->ensureHaveFile()) {
        d->canceled();
        return;
    }

    d->setProgressWindowTitle(i18nc("@title:window", "Importing Certificates"));
    d->setProgressLabelText(i18np("Importing certificates from 1 file...", "Importing certificates from %1 files...", d->files.size()));

    // TODO: use KIO here
    d->setWaitForMoreJobs(true);
    for (const QString &fn : std::as_const(d->files)) {
        QFile in(fn);
        if (!in.open(QIODevice::ReadOnly)) {
            d->error(i18n("Could not open file %1 for reading: %2", in.fileName(), in.errorString()), i18n("Certificate Import Failed"));
            d->addImportResult({fn, GpgME::UnknownProtocol, ImportType::Local, ImportResult{}, AuditLogEntry{}});
            continue;
        }
        auto data = in.readAll();
        // check for UTF-16- (or UTF-32- or UTF-8-with-BOM-)encoded text file;
        // binary certificate files don't start with a BOM, so that it's safe
        // to assume that data starting with a BOM is UTF-encoded text
        if (const auto encoding = QStringDecoder::encodingForData(data)) {
            QStringDecoder codec(*encoding);
            qCDebug(KLEOPATRA_LOG) << this << __func__ << "Decoding" << codec.name() << "encoded data";
            data = QString(codec.decode(data)).toUtf8();
        }
        d->startImport(GpgME::OpenPGP, data, fn);
        d->startImport(GpgME::CMS, data, fn);
        d->importGroupsFromFile(fn);
    }
    d->setWaitForMoreJobs(false);
}

static QStringList get_file_name(QWidget *parent)
{
    const QString certificateFilter = i18n("Certificates") + QLatin1StringView(" (*.asc *.cer *.cert *.crt *.der *.pem *.gpg *.p7c *.p12 *.pfx *.pgp *.kgrp)");
    const QString anyFilesFilter = i18n("Any files") + QLatin1StringView(" (*)");
    QString previousDir;
    if (const KSharedConfig::Ptr config = KSharedConfig::openConfig()) {
        const KConfigGroup group(config, QStringLiteral("Import Certificate"));
        previousDir = group.readPathEntry("last-open-file-directory", QDir::homePath());
    }
    const QStringList files =
        QFileDialog::getOpenFileNames(parent, i18n("Select Certificate File"), previousDir, certificateFilter + QLatin1StringView(";;") + anyFilesFilter);
    if (!files.empty())
        if (const KSharedConfig::Ptr config = KSharedConfig::openConfig()) {
            KConfigGroup group(config, QStringLiteral("Import Certificate"));
            group.writePathEntry("last-open-file-directory", QFileInfo(files.front()).path());
        }
    return files;
}

bool ImportCertificateFromFileCommand::Private::ensureHaveFile()
{
    if (files.empty()) {
        files = get_file_name(parentWidgetOrView());
    }
    return !files.empty();
}

#undef d
#undef q

#include "moc_importcertificatefromfilecommand.cpp"
