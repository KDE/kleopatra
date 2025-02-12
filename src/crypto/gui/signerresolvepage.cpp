/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signerresolvepage.h"
#include "signerresolvepage_p.h"

#include "signingcertificateselectiondialog.h"

#include "crypto/certificateresolver.h"
#include "utils/certificatepair.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <utils/kleo_assert.h>

#include <gpgme++/key.h>

#include <KLocalizedString>
#include <QDialog>

#include <QButtonGroup>
#include <QCheckBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QRadioButton>
#include <QVBoxLayout>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

namespace
{
static SignerResolvePage::Operation operationFromFlags(bool sign, bool encrypt)
{
    if (!encrypt && sign) {
        return SignerResolvePage::SignOnly;
    }
    if (!sign && encrypt) {
        return SignerResolvePage::EncryptOnly;
    }
    return SignerResolvePage::SignAndEncrypt;
}

static QString formatLabel(Protocol p, const Key &key)
{
    return i18nc("%1=protocol (S/Mime, OpenPGP), %2=certificate",
                 "Sign using %1: %2",
                 Formatting::displayName(p),
                 !key.isNull() ? Formatting::formatForComboBox(key) : i18n("No certificate selected"));
}

static std::vector<Protocol> supportedProtocols()
{
    std::vector<Protocol> protocols;
    protocols.push_back(OpenPGP);
    protocols.push_back(CMS);
    return protocols;
}
}

AbstractSigningProtocolSelectionWidget::AbstractSigningProtocolSelectionWidget(QWidget *p, Qt::WindowFlags f)
    : QWidget(p, f)
{
}

ReadOnlyProtocolSelectionWidget::ReadOnlyProtocolSelectionWidget(QWidget *p, Qt::WindowFlags f)
    : AbstractSigningProtocolSelectionWidget(p, f)
{
    auto const layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    const auto supportedProtocolsLst = supportedProtocols();
    for (const Protocol i : supportedProtocolsLst) {
        auto const l = new QLabel;
        l->setText(formatLabel(i, Key()));
        layout->addWidget(l);
        m_labels[i] = l;
    }
}

void ReadOnlyProtocolSelectionWidget::setProtocolChecked(Protocol protocol, bool checked)
{
    QLabel *const l = label(protocol);
    Q_ASSERT(l);
    l->setVisible(checked);
}

bool ReadOnlyProtocolSelectionWidget::isProtocolChecked(Protocol protocol) const
{
    QLabel *const l = label(protocol);
    Q_ASSERT(l);
    return l->isVisible();
}

std::set<Protocol> ReadOnlyProtocolSelectionWidget::checkedProtocols() const
{
    std::set<Protocol> res;
    for (const Protocol i : supportedProtocols()) {
        if (isProtocolChecked(i)) {
            res.insert(i);
        }
    }
    return res;
}

SigningProtocolSelectionWidget::SigningProtocolSelectionWidget(QWidget *parent, Qt::WindowFlags f)
    : AbstractSigningProtocolSelectionWidget(parent, f)
{
    m_buttonGroup = new QButtonGroup(this);
    connect(m_buttonGroup, &QButtonGroup::idClicked, this, &SigningProtocolSelectionWidget::userSelectionChanged);

    auto const layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    for (const Protocol i : supportedProtocols()) {
        auto const b = new QCheckBox;
        b->setText(formatLabel(i, Key()));
        m_buttons[i] = b;
        layout->addWidget(b);
        m_buttonGroup->addButton(b);
    }
    setExclusive(true);
}

void SigningProtocolSelectionWidget::setProtocolChecked(Protocol p, bool checked)
{
    Q_ASSERT(p != UnknownProtocol);
    QCheckBox *const b = button(p);
    Q_ASSERT(b);
    b->setChecked(checked);
}

bool SigningProtocolSelectionWidget::isProtocolChecked(Protocol p) const
{
    Q_ASSERT(p != UnknownProtocol);
    const QAbstractButton *const b = button(p);
    Q_ASSERT(b);
    return b->isChecked();
}

std::set<Protocol> SigningProtocolSelectionWidget::checkedProtocols() const
{
    std::set<Protocol> res;
    for (auto it = m_buttons.begin(), end = m_buttons.end(); it != end; ++it)
        if (it->second->isChecked()) {
            res.insert(it->first);
        }
    return res;
}

void SigningProtocolSelectionWidget::setExclusive(bool exclusive)
{
    if (exclusive == isExclusive()) {
        return;
    }
    m_buttonGroup->setExclusive(exclusive);
    Q_EMIT userSelectionChanged();
}

QCheckBox *SigningProtocolSelectionWidget::button(Protocol p) const
{
    const auto it = m_buttons.find(p);
    return it == m_buttons.end() ? nullptr : it->second;
}

QLabel *ReadOnlyProtocolSelectionWidget::label(Protocol p) const
{
    const auto it = m_labels.find(p);
    return it == m_labels.end() ? nullptr : it->second;
}

bool SigningProtocolSelectionWidget::isExclusive() const
{
    return m_buttonGroup->exclusive();
}

void SigningProtocolSelectionWidget::setCertificate(Protocol prot, const Key &key)
{
    QAbstractButton *const b = button(prot);
    Q_ASSERT(b);
    b->setText(formatLabel(prot, key));
}

void ReadOnlyProtocolSelectionWidget::setCertificate(Protocol prot, const Key &key)
{
    QLabel *const l = label(prot);
    l->setText(formatLabel(prot, key));
}

namespace
{

class ValidatorImpl : public SignerResolvePage::Validator
{
public:
    QString explanation() const override
    {
        return QString();
    }
    bool isComplete() const override
    {
        return true;
    }
    QString customWindowTitle() const override
    {
        return QString();
    }
};
}

class SignerResolvePage::Private
{
    friend class ::Kleo::Crypto::Gui::SignerResolvePage;
    SignerResolvePage *const q;

public:
    explicit Private(SignerResolvePage *qq);
    ~Private();

    void setOperation(Operation operation);
    void operationButtonClicked(int operation);
    void selectCertificates();
    void setCertificates(const CertificatePair &certs);
    void updateModeSelectionWidgets();
    void updateUi();
    bool protocolSelected(Protocol p) const;
    bool protocolSelectionActuallyUserMutable() const;

private:
    QButtonGroup *signEncryptGroup;
    QRadioButton *signAndEncryptRB;
    QRadioButton *encryptOnlyRB;
    QRadioButton *signOnlyRB;
    QGroupBox *signingCertificateBox;
    QLabel *signerLabelLabel;
    QLabel *signerLabel;
    QGroupBox *encryptBox;
    QCheckBox *textArmorCO;
    QPushButton *selectCertificatesButton;
    SigningProtocolSelectionWidget *signingProtocolSelectionWidget;
    ReadOnlyProtocolSelectionWidget *readOnlyProtocolSelectionWidget;
    std::vector<Protocol> presetProtocols;
    bool signingMutable;
    bool encryptionMutable;
    bool signingSelected;
    bool encryptionSelected;
    bool multipleProtocolsAllowed;
    bool protocolSelectionUserMutable;
    CertificatePair certificates;
    std::shared_ptr<SignerResolvePage::Validator> validator;
    std::shared_ptr<SigningPreferences> signingPreferences;
};

bool SignerResolvePage::Private::protocolSelectionActuallyUserMutable() const
{
    return (q->protocolSelectionUserMutable() || presetProtocols.empty()) && q->operation() == SignOnly;
}

SignerResolvePage::Private::Private(SignerResolvePage *qq)
    : q(qq)
    , presetProtocols()
    , signingMutable(true)
    , encryptionMutable(true)
    , signingSelected(false)
    , encryptionSelected(false)
    , multipleProtocolsAllowed(false)
    , protocolSelectionUserMutable(true)
    , validator(new ValidatorImpl)

{
    auto layout = new QVBoxLayout(q);

    signEncryptGroup = new QButtonGroup(q);
    q->connect(signEncryptGroup, &QButtonGroup::idClicked, q, [this](int buttonClicked) {
        operationButtonClicked(buttonClicked);
    });

    signAndEncryptRB = new QRadioButton;
    signAndEncryptRB->setText(i18n("Sign and encrypt (OpenPGP only)"));
    signAndEncryptRB->setChecked(true);
    signEncryptGroup->addButton(signAndEncryptRB, SignAndEncrypt);
    layout->addWidget(signAndEncryptRB);

    encryptOnlyRB = new QRadioButton;
    encryptOnlyRB->setText(i18n("Encrypt only"));
    signEncryptGroup->addButton(encryptOnlyRB, EncryptOnly);
    layout->addWidget(encryptOnlyRB);

    signOnlyRB = new QRadioButton;
    signOnlyRB->setText(i18n("Sign only"));
    signEncryptGroup->addButton(signOnlyRB, SignOnly);
    layout->addWidget(signOnlyRB);

    encryptBox = new QGroupBox;
    encryptBox->setTitle(i18n("Encryption Options"));
    QBoxLayout *const encryptLayout = new QVBoxLayout(encryptBox);
    textArmorCO = new QCheckBox;
    textArmorCO->setText(i18n("Text output (ASCII armor)"));
    encryptLayout->addWidget(textArmorCO);
    layout->addWidget(encryptBox);

    signingCertificateBox = new QGroupBox;
    signingCertificateBox->setTitle(i18n("Signing Options"));
    auto signerLayout = new QGridLayout(signingCertificateBox);
    signerLayout->setColumnStretch(1, 1);

    signerLabelLabel = new QLabel;
    signerLabelLabel->setText(i18n("Signer:"));
    signerLayout->addWidget(signerLabelLabel, 1, 0);
    signerLabel = new QLabel;
    signerLayout->addWidget(signerLabel, 1, 1);
    signerLabelLabel->setVisible(false);
    signerLabel->setVisible(false);

    signingProtocolSelectionWidget = new SigningProtocolSelectionWidget;
    connect(signingProtocolSelectionWidget, SIGNAL(userSelectionChanged()), q, SLOT(updateUi()));
    signerLayout->addWidget(signingProtocolSelectionWidget, 2, 0, 1, -1);

    readOnlyProtocolSelectionWidget = new ReadOnlyProtocolSelectionWidget;
    signerLayout->addWidget(readOnlyProtocolSelectionWidget, 3, 0, 1, -1);

    selectCertificatesButton = new QPushButton;
    selectCertificatesButton->setText(i18n("Change Signing Certificates..."));
    selectCertificatesButton->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    signerLayout->addWidget(selectCertificatesButton, 4, 0, 1, -1, Qt::AlignLeft);
    q->connect(selectCertificatesButton, SIGNAL(clicked()), q, SLOT(selectCertificates()));
    layout->addWidget(signingCertificateBox);
    layout->addStretch();
}

void SignerResolvePage::setValidator(const std::shared_ptr<SignerResolvePage::Validator> &validator)
{
    Q_ASSERT(validator);
    d->validator = validator;
    d->updateUi();
}

std::shared_ptr<SignerResolvePage::Validator> SignerResolvePage::validator() const
{
    return d->validator;
}

SignerResolvePage::Private::~Private()
{
}

bool SignerResolvePage::Private::protocolSelected(Protocol p) const
{
    Q_ASSERT(p != UnknownProtocol);
    return signingProtocolSelectionWidget->isProtocolChecked(p);
}

void SignerResolvePage::Private::setCertificates(const CertificatePair &certs)
{
    certificates = certs;
    readOnlyProtocolSelectionWidget->setCertificate(GpgME::OpenPGP, certs.openpgp);
    signingProtocolSelectionWidget->setCertificate(GpgME::OpenPGP, certs.openpgp);
    readOnlyProtocolSelectionWidget->setCertificate(GpgME::CMS, certs.cms);
    signingProtocolSelectionWidget->setCertificate(GpgME::CMS, certs.cms);
    updateUi();
}

void SignerResolvePage::Private::updateUi()
{
    const bool ismutable = protocolSelectionActuallyUserMutable();
    readOnlyProtocolSelectionWidget->setVisible(!ismutable);
    signingProtocolSelectionWidget->setVisible(ismutable);

    q->setExplanation(validator->explanation());
    Q_EMIT q->completeChanged();

    const QString customTitle = validator->customWindowTitle();
    if (!customTitle.isEmpty()) {
        Q_EMIT q->windowTitleChanged(customTitle);
    }
    selectCertificatesButton->setEnabled(signingProtocolSelectionWidget->checkedProtocols().size() > 0);
}

void SignerResolvePage::setProtocolSelectionUserMutable(bool ismutable)
{
    if (d->protocolSelectionUserMutable == ismutable) {
        return;
    }
    d->protocolSelectionUserMutable = ismutable;
    d->updateModeSelectionWidgets();
}

bool SignerResolvePage::protocolSelectionUserMutable() const
{
    return d->protocolSelectionUserMutable;
}

void SignerResolvePage::setMultipleProtocolsAllowed(bool allowed)
{
    if (d->multipleProtocolsAllowed == allowed) {
        return;
    }
    d->multipleProtocolsAllowed = allowed;
    d->updateModeSelectionWidgets();
}

bool SignerResolvePage::multipleProtocolsAllowed() const
{
    return d->multipleProtocolsAllowed;
}

void SignerResolvePage::Private::updateModeSelectionWidgets()
{
    const bool bothMutable = signingMutable && encryptionMutable;
    const bool noSigningPossible = !signingSelected && !signingMutable;
    const bool noEncryptionPossible = !encryptionSelected && !encryptionMutable;
    signAndEncryptRB->setChecked(signingSelected && encryptionSelected);
    signOnlyRB->setChecked(signingSelected && !encryptionSelected);
    encryptOnlyRB->setChecked(encryptionSelected && !signingSelected);
    const bool canSignAndEncrypt = !noSigningPossible && !noEncryptionPossible && bothMutable && presetProtocols != std::vector<Protocol>(1, CMS);
    const bool canSignOnly = !encryptionSelected || encryptionMutable;
    const bool canEncryptOnly = !signingSelected || signingMutable;

    signAndEncryptRB->setEnabled(canSignAndEncrypt);
    signOnlyRB->setEnabled(canSignOnly);
    encryptOnlyRB->setEnabled(canEncryptOnly);
    const bool buttonsVisible = signingMutable || encryptionMutable;
    signOnlyRB->setVisible(buttonsVisible);
    encryptOnlyRB->setVisible(buttonsVisible);
    signAndEncryptRB->setVisible(buttonsVisible);
    signingProtocolSelectionWidget->setExclusive(!multipleProtocolsAllowed);
    signingCertificateBox->setVisible(!noSigningPossible);
    encryptBox->setVisible(!noEncryptionPossible);
    updateUi();
}

void SignerResolvePage::Private::selectCertificates()
{
    QPointer<SigningCertificateSelectionDialog> dlg = new SigningCertificateSelectionDialog(q);
    dlg->setAllowedProtocols(signingProtocolSelectionWidget->checkedProtocols());
    if (dlg->exec() == QDialog::Accepted && dlg) {
        const auto certs = dlg->selectedCertificates();
        setCertificates(certs);
        if (signingPreferences && dlg->rememberAsDefault()) {
            signingPreferences->setPreferredCertificate(OpenPGP, certs.openpgp);
            signingPreferences->setPreferredCertificate(CMS, certs.cms);
        }
    }

    delete dlg;
    updateUi();
}

void SignerResolvePage::Private::operationButtonClicked(int mode_)
{
    const auto op = static_cast<SignerResolvePage::Operation>(mode_);
    signingCertificateBox->setEnabled(op != EncryptOnly);
    encryptBox->setEnabled(op != SignOnly);
    if (op == SignAndEncrypt) {
        signingProtocolSelectionWidget->setProtocolChecked(CMS, false);
        readOnlyProtocolSelectionWidget->setProtocolChecked(CMS, false);
        signingProtocolSelectionWidget->setProtocolChecked(OpenPGP, true);
        readOnlyProtocolSelectionWidget->setProtocolChecked(OpenPGP, true);
    }
    updateUi();
}

void SignerResolvePage::Private::setOperation(Operation op)
{
    switch (op) {
    case SignOnly:
        signOnlyRB->click();
        break;
    case EncryptOnly:
        encryptOnlyRB->click();
        break;
    case SignAndEncrypt:
        signAndEncryptRB->click();
        break;
    }
}

SignerResolvePage::Operation SignerResolvePage::operation() const
{
    return operationFromFlags(signingSelected(), encryptionSelected());
}

SignerResolvePage::SignerResolvePage(QWidget *parent, Qt::WindowFlags f)
    : WizardPage(parent, f)
    , d(new Private(this))
{
    setTitle(i18n("<b>Choose Operation to be Performed</b>"));
    //    setSubTitle( i18n( "TODO" ) );
    setPresetProtocol(UnknownProtocol);
    d->setCertificates({});
    d->updateModeSelectionWidgets();
    d->operationButtonClicked(EncryptOnly);
}

SignerResolvePage::~SignerResolvePage()
{
}

void SignerResolvePage::setSignersAndCandidates(const std::vector<KMime::Types::Mailbox> &signers, const std::vector<std::vector<GpgME::Key>> &keys)
{
    kleo_assert(signers.empty() || signers.size() == keys.size());

    switch (signers.size()) {
    case 0:
        d->signerLabelLabel->setVisible(false);
        d->signerLabel->setVisible(false); // TODO: use default identity?
        break;
    case 1:
        d->signerLabelLabel->setVisible(true);
        d->signerLabel->setVisible(true); // TODO: use default identity?
        d->signerLabel->setText(signers.front().prettyAddress());
        break;
    default: // > 1
        kleo_assert(!"Resolving multiple signers not implemented");
    }
    d->updateUi();
}

void SignerResolvePage::setPresetProtocol(Protocol protocol)
{
    std::vector<Protocol> protocols;
    if (protocol != CMS) {
        protocols.push_back(OpenPGP);
    }
    if (protocol != OpenPGP) {
        protocols.push_back(CMS);
    }
    setPresetProtocols(protocols);
    d->updateUi();
}

void SignerResolvePage::setPresetProtocols(const std::vector<Protocol> &protocols)
{
    d->presetProtocols = protocols;
    for (const Protocol i : supportedProtocols()) {
        const bool checked = std::find(protocols.begin(), protocols.end(), i) != protocols.end();
        d->signingProtocolSelectionWidget->setProtocolChecked(i, checked);
        d->readOnlyProtocolSelectionWidget->setProtocolChecked(i, checked);
    }
    d->updateModeSelectionWidgets();
}

std::set<Protocol> SignerResolvePage::selectedProtocols() const
{
    return d->signingProtocolSelectionWidget->checkedProtocols();
}

std::vector<Key> SignerResolvePage::signingCertificates(Protocol protocol) const
{
    std::vector<Key> result;
    if (protocol != CMS && d->signingProtocolSelectionWidget->isProtocolChecked(OpenPGP) && !d->certificates.openpgp.isNull()) {
        result.push_back(d->certificates.openpgp);
    }
    if (protocol != OpenPGP && d->signingProtocolSelectionWidget->isProtocolChecked(CMS) && !d->certificates.cms.isNull()) {
        result.push_back(d->certificates.cms);
    }
    return result;
}

std::vector<Key> SignerResolvePage::resolvedSigners() const
{
    std::vector<Key> result = signingCertificates(CMS);
    const std::vector<Key> pgp = signingCertificates(OpenPGP);
    result.insert(result.end(), pgp.begin(), pgp.end());
    return result;
}

bool SignerResolvePage::isComplete() const
{
    Q_ASSERT(d->validator);
    return d->validator->isComplete();
}

bool SignerResolvePage::encryptionSelected() const
{
    return !d->signOnlyRB->isChecked();
}

void SignerResolvePage::setEncryptionSelected(bool selected)
{
    d->encryptionSelected = selected;
    d->updateModeSelectionWidgets();
    d->setOperation(operationFromFlags(d->signingSelected, d->encryptionSelected));
}

bool SignerResolvePage::signingSelected() const
{
    return !d->encryptOnlyRB->isChecked();
}

void SignerResolvePage::setSigningSelected(bool selected)
{
    d->signingSelected = selected;
    d->updateModeSelectionWidgets();
    d->setOperation(operationFromFlags(d->signingSelected, d->encryptionSelected));
}

bool SignerResolvePage::isEncryptionUserMutable() const
{
    return d->encryptionMutable;
}

bool SignerResolvePage::isSigningUserMutable() const
{
    return d->signingMutable;
}

void SignerResolvePage::setEncryptionUserMutable(bool ismutable)
{
    d->encryptionMutable = ismutable;
    d->updateModeSelectionWidgets();
}

void SignerResolvePage::setSigningUserMutable(bool ismutable)
{
    d->signingMutable = ismutable;
    d->updateModeSelectionWidgets();
}

std::set<Protocol> SignerResolvePage::selectedProtocolsWithoutSigningCertificate() const
{
    std::set<Protocol> res;
    for (const Protocol i : selectedProtocols()) {
        if (signingCertificates(i).empty()) {
            res.insert(i);
        }
    }
    return res;
}

bool SignerResolvePage::isAsciiArmorEnabled() const
{
    return d->textArmorCO->isChecked();
}

void SignerResolvePage::setAsciiArmorEnabled(bool enabled)
{
    d->textArmorCO->setChecked(enabled);
}

void SignerResolvePage::setSigningPreferences(const std::shared_ptr<SigningPreferences> &prefs)
{
    d->signingPreferences = prefs;
    const CertificatePair certs = {prefs ? prefs->preferredCertificate(OpenPGP) : Key(), prefs ? prefs->preferredCertificate(CMS) : Key()};
    d->setCertificates(certs);
}

std::shared_ptr<SigningPreferences> SignerResolvePage::signingPreferences() const
{
    return d->signingPreferences;
}

bool SignerResolvePage::onNext()
{
    return true;
}

#include "moc_signerresolvepage.cpp"
#include "moc_signerresolvepage_p.cpp"
