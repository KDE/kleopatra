/*
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
#include <KMessageDialog>

#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QMimeData>

using namespace GpgME;
using namespace Kleo;

using namespace Qt::Literals::StringLiterals;

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
    // Don't remove this dialog, it's required to query the clipboard on wayland
    auto dialog = new KMessageDialog(KMessageDialog::Information, i18nc("@info", "Importing certificate from clipboard…"), nullptr);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    auto onClipboardAvailable = [this, dialog]() {
        dialog->close();
        d->input = qApp->clipboard()->text().toUtf8();
        d->setWaitForMoreJobs(true);
        const unsigned int classification = classifyContent(d->input);
        if (d->input.isEmpty()) {
            d->error(i18nc("@info", "The clipboard is empty. Nothing imported."));
        } else if (!mayBeAnyCertStoreType(classification)) {
            d->error(i18nc("@info", "Clipboard contents do not look like a certificate. Nothing imported."));
        } else {
            const GpgME::Protocol protocol = findProtocol(classification);
            if (protocol == GpgME::UnknownProtocol) {
                d->error(i18nc("@info", "Could not determine certificate type of clipboard contents. Nothing imported."));
            } else {
                d->startImport(protocol, d->input, i18n("Clipboard"));
            }
        }
        d->setWaitForMoreJobs(false);
    };

    if (qApp->platformName() != "wayland"_L1) {
        onClipboardAvailable();
    } else {
        dialog->show();
        // On wayland, the clipboard is not available immediately, but QClipboard::dataChanged is always triggered once we can access it.
        connect(
            qApp->clipboard(),
            &QClipboard::dataChanged,
            this,
            [onClipboardAvailable]() {
                onClipboardAvailable();
            },
            Qt::SingleShotConnection);
    }
}

#undef d
#undef q

#endif // QT_NO_CLIPBOARD

#include "moc_importcertificatefromclipboardcommand.cpp"
