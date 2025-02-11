/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "selectcertificatecommand.h"

#include <dialogs/certificateselectiondialog.h>

#include <Libkleo/KeyCache>
#include <Libkleo/KleoException>
#include <Libkleo/Stl_Util>

#include <gpgme++/key.h>

#include <gpg-error.h>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <QByteArray>
#include <QPointer>

#include <algorithm>
#include <string>

using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace GpgME;

class SelectCertificateCommand::Private
{
    friend class ::Kleo::SelectCertificateCommand;
    SelectCertificateCommand *const q;

public:
    Private(SelectCertificateCommand *qq)
        : q(qq)
        , dialog()
    {
    }

private:
    void slotDialogAccepted();
    void slotDialogRejected();
    void slotSelectedCertificates(int, const QByteArray &);

private:
    void ensureDialogCreated()
    {
        if (dialog) {
            return;
        }
        dialog = new CertificateSelectionDialog;
        q->applyWindowID(dialog);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        // dialog->setWindowTitle( i18nc( "@title", "Certificate Selection" ) );
        connect(dialog, SIGNAL(accepted()), q, SLOT(slotDialogAccepted()));
        connect(dialog, SIGNAL(rejected()), q, SLOT(slotDialogRejected()));
    }
    void ensureDialogShown()
    {
        ensureDialogCreated();
        if (dialog->isVisible()) {
            dialog->raise();
        } else {
            dialog->show();
        }
    }

private:
    QPointer<CertificateSelectionDialog> dialog;
};

SelectCertificateCommand::SelectCertificateCommand()
    : QObject()
    , AssuanCommandMixin<SelectCertificateCommand>()
    , d(new Private(this))
{
}

SelectCertificateCommand::~SelectCertificateCommand()
{
}

static const struct {
    const char *name;
    CertificateSelectionDialog::Option option;
} option_table[] = {
    {"multi", CertificateSelectionDialog::MultiSelection},
    {"sign-only", CertificateSelectionDialog::SignOnly},
    {"encrypt-only", CertificateSelectionDialog::EncryptOnly},
    {"openpgp-only", CertificateSelectionDialog::OpenPGPFormat},
    {"x509-only", CertificateSelectionDialog::CMSFormat},
    {"secret-only", CertificateSelectionDialog::SecretKeys},
};

int SelectCertificateCommand::doStart()
{
    d->ensureDialogCreated();

    CertificateSelectionDialog::Options opts;
    for (unsigned int i = 0; i < sizeof option_table / sizeof *option_table; ++i) {
        if (hasOption(option_table[i].name)) {
            opts |= option_table[i].option;
        }
    }
    if ((opts & CertificateSelectionDialog::AnyCertificate) == 0) {
        // neither sign-only nor encrypt-only => any usage
        opts |= CertificateSelectionDialog::AnyCertificate;
    }
    if ((opts & CertificateSelectionDialog::AnyFormat) == 0) {
        // neither openpgp-only nor x509-only => any protocol
        opts |= CertificateSelectionDialog::AnyFormat;
    }
    d->dialog->setOptions(opts);

    if (const int err = inquire("SELECTED_CERTIFICATES", this, SLOT(slotSelectedCertificates(int, QByteArray)))) {
        return err;
    }

    d->ensureDialogShown();

    return 0;
}

void SelectCertificateCommand::Private::slotSelectedCertificates(int err, const QByteArray &data)
{
    qCDebug(KLEOPATRA_LOG) << err << ", " << data.constData();
    if (err) {
        return;
    }
    const auto split = data.split('\n');
    std::vector<std::string> fprs;
    fprs.reserve(split.size());
    std::transform(split.cbegin(), split.cend(), std::back_inserter(fprs), std::mem_fn(&QByteArray::constData));
    const std::vector<Key> keys = KeyCache::instance()->findByKeyIDOrFingerprint(fprs);
    for (const Key &key : keys) {
        qCDebug(KLEOPATRA_LOG) << "found key " << key.userID(0).id();
    }
    if (dialog) {
        dialog->selectCertificates(keys);
    } else {
        qCWarning(KLEOPATRA_LOG) << "dialog == NULL in slotSelectedCertificates";
    }
}

void SelectCertificateCommand::doCanceled()
{
    if (d->dialog) {
        d->dialog->close();
    }
}

void SelectCertificateCommand::Private::slotDialogAccepted()
{
    try {
        QByteArray data;
        const auto selectedCertificates(dialog->selectedCertificates());
        for (const Key &key : selectedCertificates) {
            data += key.primaryFingerprint();
            data += '\n';
        }
        q->sendData(data);
        q->done();
    } catch (const Exception &e) {
        q->done(e.error(), e.message());
    } catch (const std::exception &e) {
        q->done(makeError(GPG_ERR_UNEXPECTED),
                i18n("Caught unexpected exception in SelectCertificateCommand::Private::slotDialogAccepted: %1", QString::fromLocal8Bit(e.what())));
    } catch (...) {
        q->done(makeError(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception in SelectCertificateCommand::Private::slotDialogAccepted"));
    }
}

void SelectCertificateCommand::Private::slotDialogRejected()
{
    dialog = nullptr;
    q->done(makeError(GPG_ERR_CANCELED));
}

#include "moc_selectcertificatecommand.cpp"
