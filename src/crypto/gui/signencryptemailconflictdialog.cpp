/* -*- mode: c++; c-basic-offset:4 -*-
    crypto/gui/signencryptemailconflictdialog.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signencryptemailconflictdialog.h"

#include <crypto/recipient.h>
#include <crypto/sender.h>

#include "certificateselectionline.h"
#include "dialogs/certificateselectiondialog.h"

#include "utils/gui-helper.h"
#include "utils/kleo_assert.h"
#include <Libkleo/GnuPG>

#include <Libkleo/Compliance>
#include <Libkleo/Formatting>
#include <Libkleo/Stl_Util>
#include <Libkleo/SystemInfo>

#include <gpgme++/key.h>

#include <KMime/Types>

#include <KColorScheme>
#include <KLocalizedString>

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QLabel>
#include <QLayout>
#include <QPointer>
#include <QPushButton>
#include <QRadioButton>
#include <QSignalBlocker>
#include <QToolButton>

#include <algorithm>
#include <iterator>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;
using namespace Kleo::Dialogs;
using namespace GpgME;

Q_DECLARE_METATYPE(GpgME::Key)
Q_DECLARE_METATYPE(GpgME::UserID)

static CertificateSelectionDialog *create_certificate_selection_dialog(QWidget *parent, Protocol proto)
{
    auto const dlg = new CertificateSelectionDialog(parent);
    dlg->setOptions(proto == OpenPGP   ? CertificateSelectionDialog::OpenPGPFormat
                        : proto == CMS ? CertificateSelectionDialog::CMSFormat
                                       : CertificateSelectionDialog::AnyFormat);
    return dlg;
}

static CertificateSelectionDialog *create_encryption_certificate_selection_dialog(QWidget *parent, Protocol proto, const QString &mailbox)
{
    CertificateSelectionDialog *const dlg = create_certificate_selection_dialog(parent, proto);
    dlg->setCustomLabelText(i18n("Please select an encryption certificate for recipient \"%1\"", mailbox));
    dlg->setOptions(CertificateSelectionDialog::SingleSelection | //
                    CertificateSelectionDialog::EncryptOnly | //
                    dlg->options());
    return dlg;
}

static CertificateSelectionDialog *create_signing_certificate_selection_dialog(QWidget *parent, Protocol proto, const QString &mailbox)
{
    CertificateSelectionDialog *const dlg = create_certificate_selection_dialog(parent, proto);
    dlg->setCustomLabelText(i18n("Please select a signing certificate for sender \"%1\"", mailbox));
    dlg->setOptions(CertificateSelectionDialog::SingleSelection | //
                    CertificateSelectionDialog::SignOnly | //
                    CertificateSelectionDialog::SecretKeys | //
                    dlg->options());
    return dlg;
}

static QString make_top_label_conflict_text(bool sign, bool enc)
{
    return sign && enc ? i18n(
                             "Kleopatra cannot unambiguously determine matching certificates "
                             "for all recipients/senders of the message.\n"
                             "Please select the correct certificates for each recipient:")
        : sign ? i18n(
                     "Kleopatra cannot unambiguously determine matching certificates "
                     "for the sender of the message.\n"
                     "Please select the correct certificates for the sender:")
        : enc ? i18n(
                    "Kleopatra cannot unambiguously determine matching certificates "
                    "for all recipients of the message.\n"
                    "Please select the correct certificates for each recipient:")
              : (kleo_assert_fail(sign || enc), QString());
}

static QString make_top_label_quickmode_text(bool sign, bool enc)
{
    return enc ? i18n("Please verify that correct certificates have been selected for each recipient:")
        : sign ? i18n("Please verify that the correct certificate has been selected for the sender:")
               : (kleo_assert_fail(sign || enc), QString());
}

class SignEncryptEMailConflictDialog::Private
{
    friend class ::Kleo::Crypto::Gui::SignEncryptEMailConflictDialog;
    SignEncryptEMailConflictDialog *const q;

public:
    explicit Private(SignEncryptEMailConflictDialog *qq)
        : q(qq)
        , senders()
        , recipients()
        , sign(true)
        , encrypt(true)
        , presetProtocol(UnknownProtocol)
        , ui(q)
    {
    }

private:
    void updateTopLabelText()
    {
        ui.conflictTopLB.setText(make_top_label_conflict_text(sign, encrypt));
        ui.quickModeTopLB.setText(make_top_label_quickmode_text(sign, encrypt));
    }

    void showHideWidgets()
    {
        const Protocol proto = q->selectedProtocol();
        const bool quickMode = q->isQuickMode();

        const bool needProtocolSelection = presetProtocol == UnknownProtocol;

        const bool needShowAllRecipientsCB = quickMode ? false
            : needProtocolSelection                    ? needShowAllRecipients(OpenPGP) || needShowAllRecipients(CMS)
                                                       : needShowAllRecipients(proto);

        ui.showAllRecipientsCB.setVisible(needShowAllRecipientsCB);

        ui.pgpRB.setVisible(needProtocolSelection);
        ui.cmsRB.setVisible(needProtocolSelection);

        const bool showAll = !needShowAllRecipientsCB || ui.showAllRecipientsCB.isChecked();

        bool first;
        first = true;
        for (const CertificateSelectionLine &line : std::as_const(ui.signers)) {
            line.showHide(proto, first, showAll, sign);
        }
        ui.selectSigningCertificatesGB.setVisible(sign && (showAll || !first));

        first = true;
        for (const CertificateSelectionLine &line : std::as_const(ui.recipients)) {
            line.showHide(proto, first, showAll, encrypt);
        }
        ui.selectEncryptionCertificatesGB.setVisible(encrypt && (showAll || !first));
    }

    bool needShowAllRecipients(Protocol proto) const
    {
        if (sign) {
            if (const unsigned int num = std::count_if(ui.signers.cbegin(), ui.signers.cend(), [proto](const CertificateSelectionLine &l) {
                    return l.wasInitiallyAmbiguous(proto);
                })) {
                if (num != ui.signers.size()) {
                    return true;
                }
            }
        }
        if (encrypt) {
            if (const unsigned int num = std::count_if(ui.recipients.cbegin(), ui.recipients.cend(), [proto](const CertificateSelectionLine &l) {
                    return l.wasInitiallyAmbiguous(proto);
                })) {
                if (num != ui.recipients.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    void createSendersAndRecipients()
    {
        ui.clearSendersAndRecipients();

        ui.addSelectSigningCertificatesGB();
        for (const Sender &s : std::as_const(senders)) {
            addSigner(s);
        }

        ui.addSelectEncryptionCertificatesGB();
        for (const Sender &s : std::as_const(senders)) {
            addRecipient(s);
        }
        for (const Recipient &r : std::as_const(recipients)) {
            addRecipient(r);
        }
    }

    void addSigner(const Sender &s)
    {
        ui.addSigner(s.mailbox().prettyAddress(),
                     s.signingCertificateCandidates(OpenPGP),
                     s.isSigningAmbiguous(OpenPGP),
                     s.signingCertificateCandidates(CMS),
                     s.isSigningAmbiguous(CMS),
                     q);
    }

    void addRecipient(const Sender &s)
    {
        ui.addRecipient(s.mailbox().prettyAddress(),
                        s.encryptToSelfCertificateCandidates(OpenPGP),
                        s.isEncryptionAmbiguous(OpenPGP),
                        s.encryptToSelfCertificateCandidates(CMS),
                        s.isEncryptionAmbiguous(CMS),
                        q);
    }

    void addRecipient(const Recipient &r)
    {
        ui.addRecipient(r.mailbox().prettyAddress(),
                        r.encryptionCertificateCandidates(OpenPGP),
                        r.isEncryptionAmbiguous(OpenPGP),
                        r.encryptionCertificateCandidates(CMS),
                        r.isEncryptionAmbiguous(CMS),
                        q);
    }

    bool isComplete(Protocol proto) const;

private:
    void updateComplianceStatus()
    {
        if (!DeVSCompliance::isCompliant()) {
            return;
        }
        if (q->selectedProtocol() == UnknownProtocol || (q->resolvedSigningKeys().empty() && q->resolvedEncryptionKeys().empty())) {
            return;
        }
        // Handle compliance
        bool de_vs = true;
        for (const auto &key : q->resolvedSigningKeys()) {
            if (!DeVSCompliance::keyIsCompliant(key)) {
                de_vs = false;
                break;
            }
        }
        if (de_vs) {
            for (const auto &key : q->resolvedEncryptionKeys()) {
                if (!DeVSCompliance::keyIsCompliant(key)) {
                    de_vs = false;
                    break;
                }
            }
        }

        auto btn = ui.buttonBox.button(QDialogButtonBox::Ok);

        DeVSCompliance::decorate(btn, de_vs);
        ui.complianceLB.setText(DeVSCompliance::name(de_vs));
        ui.complianceLB.setVisible(true);
    }

    void updateDialogStatus()
    {
        ui.setOkButtonEnabled(q->isComplete());
        updateComplianceStatus();
    }
    void slotCompleteChanged()
    {
        updateDialogStatus();
    }
    void slotShowAllRecipientsToggled(bool)
    {
        showHideWidgets();
    }
    void slotProtocolChanged()
    {
        showHideWidgets();
        updateDialogStatus();
    }
    void slotCertificateSelectionDialogRequested()
    {
        const QObject *const s = q->sender();
        const Protocol proto = q->selectedProtocol();
        QPointer<CertificateSelectionDialog> dlg;
        for (const CertificateSelectionLine &l : std::as_const(ui.signers))
            if (s == l.toolButton()) {
                dlg = create_signing_certificate_selection_dialog(q, proto, l.mailboxText());
                if (dlg->exec()) {
                    l.addAndSelectCertificate(dlg->selectedCertificate());
                }
                // ### switch to key.protocol(), in case proto == UnknownProtocol
                break;
            }
        for (const CertificateSelectionLine &l : std::as_const(ui.recipients))
            if (s == l.toolButton()) {
                dlg = create_encryption_certificate_selection_dialog(q, proto, l.mailboxText());
                if (dlg->exec()) {
                    l.addAndSelectCertificate(dlg->selectedCertificate());
                }
                // ### switch to key.protocol(), in case proto == UnknownProtocol
                break;
            }
#ifndef Q_OS_WIN
        // This leads to a crash on Windows. We don't really
        // leak memory here anyway because the destruction of the
        // dialog happens when the parent (q) is destroyed anyway.
        delete dlg;
#endif
    }

private:
    std::vector<Sender> senders;
    std::vector<Recipient> recipients;

    bool sign : 1;
    bool encrypt : 1;
    Protocol presetProtocol;

private:
    struct Ui {
        QLabel conflictTopLB, quickModeTopLB;
        QCheckBox showAllRecipientsCB;
        QRadioButton pgpRB, cmsRB;
        QGroupBox selectSigningCertificatesGB;
        QGroupBox selectEncryptionCertificatesGB;
        QCheckBox quickModeCB;
        QDialogButtonBox buttonBox;
        QVBoxLayout vlay;
        QHBoxLayout hlay;
        QHBoxLayout hlay2;
        QGridLayout glay;
        std::vector<CertificateSelectionLine> signers, recipients;
        QLabel complianceLB;

        void setOkButtonEnabled(bool enable)
        {
            return buttonBox.button(QDialogButtonBox::Ok)->setEnabled(enable);
        }

        explicit Ui(SignEncryptEMailConflictDialog *q)
            : conflictTopLB(make_top_label_conflict_text(true, true), q)
            , quickModeTopLB(make_top_label_quickmode_text(true, true), q)
            , showAllRecipientsCB(i18n("Show all recipients"), q)
            , pgpRB(i18n("OpenPGP"), q)
            , cmsRB(i18n("S/MIME"), q)
            , selectSigningCertificatesGB(i18n("Select Signing Certificate"), q)
            , selectEncryptionCertificatesGB(i18n("Select Encryption Certificate"), q)
            , quickModeCB(i18n("Only show this dialog in case of conflicts (experimental)"), q)
            , buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, q)
            , vlay(q)
            , hlay()
            , glay()
            , signers()
            , recipients()
        {
            Q_SET_OBJECT_NAME(conflictTopLB);
            Q_SET_OBJECT_NAME(quickModeTopLB);
            Q_SET_OBJECT_NAME(showAllRecipientsCB);
            Q_SET_OBJECT_NAME(pgpRB);
            Q_SET_OBJECT_NAME(cmsRB);
            Q_SET_OBJECT_NAME(selectSigningCertificatesGB);
            Q_SET_OBJECT_NAME(selectEncryptionCertificatesGB);
            Q_SET_OBJECT_NAME(quickModeCB);
            Q_SET_OBJECT_NAME(buttonBox);
            Q_SET_OBJECT_NAME(hlay);
            Q_SET_OBJECT_NAME(glay);
            Q_SET_OBJECT_NAME(vlay);

            q->setWindowTitle(i18nc("@title:window", "Select Certificates for Message"));

            conflictTopLB.hide();

            selectSigningCertificatesGB.setFlat(true);
            selectEncryptionCertificatesGB.setFlat(true);
            selectSigningCertificatesGB.setAlignment(Qt::AlignCenter);
            selectEncryptionCertificatesGB.setAlignment(Qt::AlignCenter);

            glay.setColumnStretch(2, 1);
            glay.setColumnStretch(3, 1);

            vlay.setSizeConstraint(QLayout::SetMinimumSize);

            vlay.addWidget(&conflictTopLB);
            vlay.addWidget(&quickModeTopLB);

            hlay.addWidget(&showAllRecipientsCB);
            hlay.addStretch(1);
            hlay.addWidget(&pgpRB);
            hlay.addWidget(&cmsRB);
            vlay.addLayout(&hlay);

            addSelectSigningCertificatesGB();
            addSelectEncryptionCertificatesGB();
            vlay.addLayout(&glay);

            vlay.addStretch(1);

            complianceLB.setVisible(false);
            hlay2.addStretch(1);
            hlay2.addWidget(&complianceLB, 0, Qt::AlignRight);
            hlay2.addWidget(&buttonBox, 0, Qt::AlignRight);

            vlay.addWidget(&quickModeCB, 0, Qt::AlignRight);
            vlay.addLayout(&hlay2);

            connect(&buttonBox, &QDialogButtonBox::accepted, q, &SignEncryptEMailConflictDialog::accept);
            connect(&buttonBox, &QDialogButtonBox::rejected, q, &SignEncryptEMailConflictDialog::reject);

            connect(&showAllRecipientsCB, SIGNAL(toggled(bool)), q, SLOT(slotShowAllRecipientsToggled(bool)));
            connect(&pgpRB, SIGNAL(toggled(bool)), q, SLOT(slotProtocolChanged()));
            connect(&cmsRB, SIGNAL(toggled(bool)), q, SLOT(slotProtocolChanged()));
        }

        void clearSendersAndRecipients()
        {
            std::vector<CertificateSelectionLine> sig, enc;
            sig.swap(signers);
            enc.swap(recipients);
            std::for_each(sig.begin(), sig.end(), std::mem_fn(&CertificateSelectionLine::kill));
            std::for_each(enc.begin(), enc.end(), std::mem_fn(&CertificateSelectionLine::kill));
            glay.removeWidget(&selectSigningCertificatesGB);
            glay.removeWidget(&selectEncryptionCertificatesGB);
        }

        void addSelectSigningCertificatesGB()
        {
            glay.addWidget(&selectSigningCertificatesGB, glay.rowCount(), 0, 1, CertificateSelectionLine::NumColumns);
        }
        void addSelectEncryptionCertificatesGB()
        {
            glay.addWidget(&selectEncryptionCertificatesGB, glay.rowCount(), 0, 1, CertificateSelectionLine::NumColumns);
        }

        void addSigner(const QString &mailbox, const std::vector<Key> &pgp, bool pgpAmbiguous, const std::vector<Key> &cms, bool cmsAmbiguous, QWidget *q)
        {
            CertificateSelectionLine line(i18n("From:"), mailbox, pgp, pgpAmbiguous, cms, cmsAmbiguous, q, glay);
            signers.push_back(line);
        }

        void addRecipient(const QString &mailbox, const std::vector<Key> &pgp, bool pgpAmbiguous, const std::vector<Key> &cms, bool cmsAmbiguous, QWidget *q)
        {
            CertificateSelectionLine line(i18n("To:"), mailbox, pgp, pgpAmbiguous, cms, cmsAmbiguous, q, glay);
            recipients.push_back(line);
        }

    } ui;
};

SignEncryptEMailConflictDialog::SignEncryptEMailConflictDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
}

SignEncryptEMailConflictDialog::~SignEncryptEMailConflictDialog()
{
}

void SignEncryptEMailConflictDialog::setPresetProtocol(Protocol p)
{
    if (p == d->presetProtocol) {
        return;
    }
    const QSignalBlocker pgpBlocker(d->ui.pgpRB);
    const QSignalBlocker cmsBlocker(d->ui.cmsRB);
    really_check(d->ui.pgpRB, p == OpenPGP);
    really_check(d->ui.cmsRB, p == CMS);
    d->presetProtocol = p;
    d->showHideWidgets();
    d->updateDialogStatus();
}

Protocol SignEncryptEMailConflictDialog::selectedProtocol() const
{
    if (d->presetProtocol != UnknownProtocol) {
        return d->presetProtocol;
    }
    if (d->ui.pgpRB.isChecked()) {
        return OpenPGP;
    }
    if (d->ui.cmsRB.isChecked()) {
        return CMS;
    }
    return UnknownProtocol;
}

void SignEncryptEMailConflictDialog::setSubject(const QString &subject)
{
    setWindowTitle(i18nc("@title:window", "Select Certificates for Message \"%1\"", subject));
}

void SignEncryptEMailConflictDialog::setSign(bool sign)
{
    if (sign == d->sign) {
        return;
    }
    d->sign = sign;
    d->updateTopLabelText();
    d->showHideWidgets();
    d->updateDialogStatus();
}

void SignEncryptEMailConflictDialog::setEncrypt(bool encrypt)
{
    if (encrypt == d->encrypt) {
        return;
    }
    d->encrypt = encrypt;
    d->updateTopLabelText();
    d->showHideWidgets();
    d->updateDialogStatus();
}

void SignEncryptEMailConflictDialog::setSenders(const std::vector<Sender> &senders)
{
    if (senders == d->senders) {
        return;
    }
    d->senders = senders;
    d->createSendersAndRecipients();
    d->showHideWidgets();
    d->updateDialogStatus();
}

void SignEncryptEMailConflictDialog::setRecipients(const std::vector<Recipient> &recipients)
{
    if (d->recipients == recipients) {
        return;
    }
    d->recipients = recipients;
    d->createSendersAndRecipients();
    d->showHideWidgets();
    d->updateDialogStatus();
}

void SignEncryptEMailConflictDialog::pickProtocol()
{
    if (selectedProtocol() != UnknownProtocol) {
        return; // already picked
    }

    const bool pgp = d->isComplete(OpenPGP);
    const bool cms = d->isComplete(CMS);

    if (pgp && !cms) {
        d->ui.pgpRB.setChecked(true);
    } else if (cms && !pgp) {
        d->ui.cmsRB.setChecked(true);
    }
}

bool SignEncryptEMailConflictDialog::isComplete() const
{
    const Protocol proto = selectedProtocol();
    return proto != UnknownProtocol && d->isComplete(proto);
}

bool SignEncryptEMailConflictDialog::Private::isComplete(Protocol proto) const
{
    return (!sign
            || std::none_of(ui.signers.cbegin(), //
                            ui.signers.cend(),
                            [proto](const CertificateSelectionLine &l) {
                                return l.isStillAmbiguous(proto);
                            }))
        && (!encrypt
            || std::none_of(ui.recipients.cbegin(), //
                            ui.recipients.cend(),
                            [proto](const CertificateSelectionLine &l) {
                                return l.isStillAmbiguous(proto);
                            }));
}

static std::vector<Key> get_keys(const std::vector<CertificateSelectionLine> &lines, Protocol proto)
{
    if (proto == UnknownProtocol) {
        return std::vector<Key>();
    }
    Q_ASSERT(proto == OpenPGP || proto == CMS);

    std::vector<Key> keys;
    keys.reserve(lines.size());
    std::transform(lines.cbegin(), lines.cend(), std::back_inserter(keys), [proto](const CertificateSelectionLine &l) {
        return l.key(proto);
    });
    return keys;
}

std::vector<Key> SignEncryptEMailConflictDialog::resolvedSigningKeys() const
{
    return d->sign ? get_keys(d->ui.signers, selectedProtocol()) : std::vector<Key>();
}

std::vector<Key> SignEncryptEMailConflictDialog::resolvedEncryptionKeys() const
{
    return d->encrypt ? get_keys(d->ui.recipients, selectedProtocol()) : std::vector<Key>();
}

void SignEncryptEMailConflictDialog::setQuickMode(bool on)
{
    d->ui.quickModeCB.setChecked(on);
}

bool SignEncryptEMailConflictDialog::isQuickMode() const
{
    return d->ui.quickModeCB.isChecked();
}

void SignEncryptEMailConflictDialog::setConflict(bool conflict)
{
    d->ui.conflictTopLB.setVisible(conflict);
    d->ui.quickModeTopLB.setVisible(!conflict);
}

#include "moc_signencryptemailconflictdialog.cpp"
