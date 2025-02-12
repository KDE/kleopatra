/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signemailwizard.h"

#include "signerresolvepage.h"

#include <settings.h>

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace Kleo::Crypto::Gui;
using namespace GpgME;

namespace
{

class SignerResolveValidator : public SignerResolvePage::Validator
{
public:
    explicit SignerResolveValidator(SignerResolvePage *page);
    bool isComplete() const override;
    QString explanation() const override;
    void update() const;
    QString customWindowTitle() const override
    {
        return QString();
    }

private:
    SignerResolvePage *m_page;
    mutable QString expl;
    mutable bool complete;
};
}

SignerResolveValidator::SignerResolveValidator(SignerResolvePage *page)
    : SignerResolvePage::Validator()
    , m_page(page)
    , complete(true)
{
    Q_ASSERT(m_page);
}

void SignerResolveValidator::update() const
{
    const bool haveSelected = !m_page->selectedProtocols().empty();
    const std::set<Protocol> missing = m_page->selectedProtocolsWithoutSigningCertificate();

    complete = haveSelected && missing.empty();
    expl.clear();
    if (complete) {
        return;
    }
    if (!haveSelected) {
        expl = i18n("You need to select a signing certificate to proceed.");
        return;
    }

    Q_ASSERT(missing.size() <= 2);
    if (missing.size() == 1) {
        if (missing.find(OpenPGP) != missing.end()) {
            expl = i18n("You need to select an OpenPGP signing certificate to proceed.");
        } else {
            expl = i18n("You need to select an S/MIME signing certificate to proceed.");
        }
    } else {
        expl = i18n("You need to select an OpenPGP signing certificate and an S/MIME signing certificate to proceed.");
    }
}

QString SignerResolveValidator::explanation() const
{
    update();
    return expl;
}

bool SignerResolveValidator::isComplete() const
{
    update();
    return complete;
}

SignEMailWizard::SignEMailWizard(QWidget *parent, Qt::WindowFlags f)
    : SignEncryptWizard(parent, f)
{
    setWindowTitle(i18nc("@title:window", "Sign Text"));

    std::vector<int> pageOrder;
    setSignerResolvePageValidator(std::shared_ptr<SignerResolveValidator>(new SignerResolveValidator(signerResolvePage())));
    pageOrder.push_back(Page::ResolveSigner);
    pageOrder.push_back(Page::Result);
    setPageOrder(pageOrder);
    setCommitPage(Page::ResolveSigner);
    setEncryptionSelected(false);
    setEncryptionUserMutable(false);
    setSigningSelected(true);
    setSigningUserMutable(false);
    signerResolvePage()->setProtocolSelectionUserMutable(false);
    setMultipleProtocolsAllowed(false);

    setKeepResultPageOpenWhenDone(Kleo::Settings{}.showResultsAfterSigningClipboard());
}

SignEMailWizard::~SignEMailWizard()
{
    // always save the setting even if the dialog was canceled (the dialog's result
    // is always Rejected because the result page has no Finish button)
    Kleo::Settings settings;
    settings.setShowResultsAfterSigningClipboard(keepResultPageOpenWhenDone());
    settings.save();
}

#include "moc_signemailwizard.cpp"
