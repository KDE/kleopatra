/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signencryptwizard.h"

#include "objectspage.h"
#include "resolverecipientspage.h"
#include "resultpage.h"
#include "signerresolvepage.h"

#include <crypto/certificateresolver.h>
#include <crypto/task.h>
#include <crypto/taskcollection.h>

#include <utils/kleo_assert.h>

#include <Libkleo/Stl_Util>

#include <gpgme++/key.h>

#include <KConfig>

#include <QFileInfo>
#include <QTimer>

#include <KSharedConfig>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;
using namespace GpgME;
using namespace KMime::Types;

class SignEncryptWizard::Private
{
    friend class ::Kleo::Crypto::Gui::SignEncryptWizard;
    SignEncryptWizard *const q;

public:
    explicit Private(SignEncryptWizard *qq);
    ~Private();

    void setCommitPage(Page::Id page);

    ResolveRecipientsPage *const recipientResolvePage;
    SignerResolvePage *const signerResolvePage;
    ObjectsPage *const objectsPage;
    ResultPage *const resultPage;
};

SignEncryptWizard::Private::Private(SignEncryptWizard *qq)
    : q(qq)
    , recipientResolvePage(new ResolveRecipientsPage)
    , signerResolvePage(new SignerResolvePage)
    , objectsPage(new ObjectsPage)
    , resultPage(new ResultPage)
{
    q->setPage(Page::ResolveSigner, signerResolvePage);
    q->setPage(Page::Objects, objectsPage);
    q->setPage(Page::ResolveRecipients, recipientResolvePage);
    q->setPage(Page::Result, resultPage);
    // TODO: move the RecipientPreferences creation out of here, don't create a new instance for each wizard
    recipientResolvePage->setRecipientPreferences(std::shared_ptr<RecipientPreferences>(new KConfigBasedRecipientPreferences(KSharedConfig::openConfig())));
    signerResolvePage->setSigningPreferences(std::shared_ptr<SigningPreferences>(new KConfigBasedSigningPreferences(KSharedConfig::openConfig())));
    q->resize(QSize(640, 480).expandedTo(q->sizeHint()));
}

void SignEncryptWizard::onNext(int currentId)
{
    if (currentId == Page::ResolveRecipients) {
        QTimer::singleShot(0, this, &SignEncryptWizard::recipientsResolved);
    }
    if (currentId == Page::ResolveSigner) {
        // FIXME: Sign&Encrypt is only supported by OpenPGP. Remove this when we support this for CMS, too
        if (encryptionSelected() && signingSelected()) {
            setPresetProtocol(OpenPGP);
        }
        QTimer::singleShot(0, this, &SignEncryptWizard::signersResolved);
    }
    if (currentId == Page::Objects) {
        QTimer::singleShot(0, this, &SignEncryptWizard::objectsResolved);
    }
}

SignEncryptWizard::Private::~Private()
{
}

SignEncryptWizard::SignEncryptWizard(QWidget *p, Qt::WindowFlags f)
    : Wizard(p, f)
    , d(new Private(this))
{
}

SignEncryptWizard::~SignEncryptWizard()
{
}

void SignEncryptWizard::setCommitPage(Page::Id page)
{
    d->setCommitPage(page);
}

void SignEncryptWizard::Private::setCommitPage(Page::Id page)
{
    q->page(Page::ResolveSigner)->setCommitPage(false);
    q->page(Page::ResolveRecipients)->setCommitPage(false);
    q->page(Page::Objects)->setCommitPage(false);
    q->page(Page::Result)->setCommitPage(false);
    q->page(page)->setCommitPage(true);
}

void SignEncryptWizard::setPresetProtocol(Protocol proto)
{
    d->signerResolvePage->setPresetProtocol(proto);
    d->signerResolvePage->setProtocolSelectionUserMutable(proto == UnknownProtocol);
    d->recipientResolvePage->setPresetProtocol(proto);
}

GpgME::Protocol SignEncryptWizard::selectedProtocol() const
{
    return d->recipientResolvePage->selectedProtocol();
}

GpgME::Protocol SignEncryptWizard::presetProtocol() const
{
    return d->recipientResolvePage->presetProtocol();
}

void SignEncryptWizard::setEncryptionSelected(bool selected)
{
    d->signerResolvePage->setEncryptionSelected(selected);
}

void SignEncryptWizard::setSigningSelected(bool selected)
{
    d->signerResolvePage->setSigningSelected(selected);
}

bool SignEncryptWizard::isSigningUserMutable() const
{
    return d->signerResolvePage->isSigningUserMutable();
}

void SignEncryptWizard::setSigningUserMutable(bool isMutable)
{
    d->signerResolvePage->setSigningUserMutable(isMutable);
}

bool SignEncryptWizard::isEncryptionUserMutable() const
{
    return d->signerResolvePage->isEncryptionUserMutable();
}

bool SignEncryptWizard::isMultipleProtocolsAllowed() const
{
    return d->recipientResolvePage->multipleProtocolsAllowed();
}

void SignEncryptWizard::setMultipleProtocolsAllowed(bool allowed)
{
    d->signerResolvePage->setMultipleProtocolsAllowed(allowed);
    d->recipientResolvePage->setMultipleProtocolsAllowed(allowed);
}

void SignEncryptWizard::setEncryptionUserMutable(bool isMutable)
{
    d->signerResolvePage->setEncryptionUserMutable(isMutable);
}

void SignEncryptWizard::setFiles(const QStringList &files)
{
    d->objectsPage->setFiles(files);
}

QFileInfoList SignEncryptWizard::resolvedFiles() const
{
    const QStringList files = d->objectsPage->files();
    QFileInfoList fileInfos;
    for (const QString &i : files) {
        fileInfos.push_back(QFileInfo(i));
    }
    return fileInfos;
}

bool SignEncryptWizard::signingSelected() const
{
    return d->signerResolvePage->signingSelected();
}

bool SignEncryptWizard::encryptionSelected() const
{
    return d->signerResolvePage->encryptionSelected();
}

void SignEncryptWizard::setSignersAndCandidates(const std::vector<Mailbox> &signers, const std::vector<std::vector<Key>> &keys)
{
    d->signerResolvePage->setSignersAndCandidates(signers, keys);
}

void SignEncryptWizard::setTaskCollection(const std::shared_ptr<TaskCollection> &coll)
{
    kleo_assert(coll);
    d->resultPage->setTaskCollection(coll);
}

std::vector<Key> SignEncryptWizard::resolvedCertificates() const
{
    return d->recipientResolvePage->resolvedCertificates();
}

std::vector<Key> SignEncryptWizard::resolvedSigners() const
{
    return d->signerResolvePage->resolvedSigners();
}

bool SignEncryptWizard::isAsciiArmorEnabled() const
{
    return d->signerResolvePage->isAsciiArmorEnabled();
}

void SignEncryptWizard::setAsciiArmorEnabled(bool enabled)
{
    d->signerResolvePage->setAsciiArmorEnabled(enabled);
}

bool SignEncryptWizard::recipientsUserMutable() const
{
    return d->recipientResolvePage->recipientsUserMutable();
}

void SignEncryptWizard::setRecipientsUserMutable(bool isMutable)
{
    d->recipientResolvePage->setRecipientsUserMutable(isMutable);
}

void SignEncryptWizard::setSignerResolvePageValidator(const std::shared_ptr<SignerResolvePage::Validator> &validator)
{
    d->signerResolvePage->setValidator(validator);
}

Gui::SignerResolvePage *SignEncryptWizard::signerResolvePage()
{
    return d->signerResolvePage;
}

const Gui::SignerResolvePage *SignEncryptWizard::signerResolvePage() const
{
    return d->signerResolvePage;
}

Gui::ResolveRecipientsPage *SignEncryptWizard::resolveRecipientsPage()
{
    return d->recipientResolvePage;
}

Gui::ObjectsPage *SignEncryptWizard::objectsPage()
{
    return d->objectsPage;
}

Gui::ResultPage *SignEncryptWizard::resultPage()
{
    return d->resultPage;
}

bool SignEncryptWizard::keepResultPageOpenWhenDone() const
{
    return d->resultPage->keepOpenWhenDone();
}

void SignEncryptWizard::setKeepResultPageOpenWhenDone(bool keep)
{
    d->resultPage->setKeepOpenWhenDone(keep);
}

#include "moc_signencryptwizard.cpp"
