/* -*- mode: c++; c-basic-offset:4 -*-
    importcertificatefromclipboardcommand.cpp

    This clipboard is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "importcertificatefromclipboardcommand.h"

#ifndef QT_NO_CLIPBOARD

#include "importcertificatescommand_p.h"

#include <Libkleo/Classify>

#include <gpgme++/global.h>

#include <KLocalizedString>

#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QMimeData>

using namespace GpgME;
using namespace Kleo;

class ImportCertificateFromClipboardCommand::Private : public ImportCertificatesCommand::Private
{
    friend class ::ImportCertificateFromClipboardCommand;
    ImportCertificateFromClipboardCommand *q_func() const
    {
        return static_cast<ImportCertificateFromClipboardCommand *>(q);
    }

public:
    explicit Private(ImportCertificateFromClipboardCommand *qq, KeyListController *c);
    ~Private() override;

    bool ensureHaveClipboard();

private:
    QByteArray input;
};

ImportCertificateFromClipboardCommand::Private *ImportCertificateFromClipboardCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ImportCertificateFromClipboardCommand::Private *ImportCertificateFromClipboardCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

ImportCertificateFromClipboardCommand::Private::Private(ImportCertificateFromClipboardCommand *qq, KeyListController *c)
    : ImportCertificatesCommand::Private(qq, c)
{
}

ImportCertificateFromClipboardCommand::Private::~Private()
{
}

// static
bool ImportCertificateFromClipboardCommand::canImportCurrentClipboard()
{
    if (const QClipboard *clip = QApplication::clipboard())
        if (const QMimeData *mime = clip->mimeData())
            return mime->hasText() && mayBeAnyCertStoreType(classifyContent(mime->text().toUtf8()));
    return false;
}

#define d d_func()
#define q q_func()

ImportCertificateFromClipboardCommand::ImportCertificateFromClipboardCommand(KeyListController *p)
    : ImportCertificatesCommand(new Private(this, p))
{
}

ImportCertificateFromClipboardCommand::ImportCertificateFromClipboardCommand(QAbstractItemView *v, KeyListController *p)
    : ImportCertificatesCommand(v, new Private(this, p))
{
}

ImportCertificateFromClipboardCommand::~ImportCertificateFromClipboardCommand()
{
}

void ImportCertificateFromClipboardCommand::doStart()
{
    if (!d->ensureHaveClipboard()) {
        d->canceled();
        return;
    }

    d->setWaitForMoreJobs(true);
    const unsigned int classification = classifyContent(d->input);
    if (!mayBeAnyCertStoreType(classification)) {
        d->error(i18n("Clipboard contents do not look like a certificate."), i18n("Certificate Import Failed"));
    } else {
        const GpgME::Protocol protocol = findProtocol(classification);
        if (protocol == GpgME::UnknownProtocol) {
            d->error(i18n("Could not determine certificate type of clipboard contents."), i18n("Certificate Import Failed"));
        } else {
            d->startImport(protocol, d->input, i18n("Clipboard"));
        }
    }
    d->setWaitForMoreJobs(false);
}

bool ImportCertificateFromClipboardCommand::Private::ensureHaveClipboard()
{
    if (input.isEmpty())
        if (const QClipboard *cb = qApp->clipboard()) {
            input = cb->text().toUtf8();
        }
    return !input.isEmpty();
}

#undef d
#undef q

#endif // QT_NO_CLIPBOARD

#include "moc_importcertificatefromclipboardcommand.cpp"
