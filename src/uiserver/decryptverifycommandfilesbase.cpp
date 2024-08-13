/* -*- mode: c++; c-basic-offset:4 -*-
    uiserver/decryptverifycommandfilesbase.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "decryptverifycommandfilesbase.h"
#include "fileoperationspreferences.h"

#include <crypto/decryptverifytask.h>

#include "crypto/autodecryptverifyfilescontroller.h"
#include "crypto/decryptverifyfilescontroller.h"

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <Libkleo/Formatting>
#include <Libkleo/Hex>
#include <Libkleo/KeyCache>
#include <Libkleo/KleoException>
#include <Libkleo/Stl_Util>

#include <gpgme++/decryptionresult.h>
#include <gpgme++/error.h>
#include <gpgme++/key.h>
#include <gpgme++/verificationresult.h>

#include <KLocalizedString>

#include <QFileInfo>

#include <gpg-error.h>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Formatting;
using namespace GpgME;

class DecryptVerifyCommandFilesBase::Private : public QObject
{
    Q_OBJECT
    friend class ::Kleo::DecryptVerifyCommandFilesBase;
    DecryptVerifyCommandFilesBase *const q;

public:
    explicit Private(DecryptVerifyCommandFilesBase *qq)
        : QObject()
        , q(qq)
        , controller()
    {
    }

    ~Private() override
    {
    }

    void checkForErrors() const;

public Q_SLOTS:
    void slotProgress(const QString &what, int current, int total);
    void verificationResult(const GpgME::VerificationResult &);
    void slotDone()
    {
        q->done();
    }
    void slotError(int err, const QString &details)
    {
        q->done(err, details);
    }

public:
private:
    std::shared_ptr<DecryptVerifyFilesController> controller;
};

DecryptVerifyCommandFilesBase::DecryptVerifyCommandFilesBase()
    : AssuanCommandMixin<DecryptVerifyCommandFilesBase>()
    , d(new Private(this))
{
}

DecryptVerifyCommandFilesBase::~DecryptVerifyCommandFilesBase()
{
}

int DecryptVerifyCommandFilesBase::doStart()
{
    d->checkForErrors();

    FileOperationsPreferences prefs;
    if (prefs.autoDecryptVerify()) {
        d->controller.reset(new AutoDecryptVerifyFilesController());
    } else {
        d->controller.reset(new DecryptVerifyFilesController(shared_from_this()));
    }

    d->controller->setOperation(operation());
    d->controller->setFiles(fileNames());

    QObject::connect(d->controller.get(), &Controller::done, d.get(), &Private::slotDone, Qt::QueuedConnection);
    QObject::connect(d->controller.get(), &Controller::error, d.get(), &Private::slotError, Qt::QueuedConnection);
    QObject::connect(d->controller.get(), &DecryptVerifyFilesController::verificationResult, d.get(), &Private::verificationResult, Qt::QueuedConnection);

    d->controller->start();

    return 0;
}

namespace
{

struct is_file {
    bool operator()(const QString &file) const
    {
        return QFileInfo(file).isFile();
    }
};
}

void DecryptVerifyCommandFilesBase::Private::checkForErrors() const
{
    if (!q->senders().empty())
        throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("Cannot use SENDER"));

    if (!q->recipients().empty())
        throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("Cannot use RECIPIENT"));

    const unsigned int numInputs = q->inputs().size();
    const unsigned int numMessages = q->messages().size();
    const unsigned int numOutputs = q->outputs().size();

    if (numInputs) {
        throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("INPUT present"));
    }
    if (numMessages) {
        throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("MESSAGE present"));
    }
    if (numOutputs) {
        throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("OUTPUT present"));
    }
    const QStringList fileNames = q->fileNames();
    if (fileNames.empty())
        throw Exception(makeError(GPG_ERR_ASS_NO_INPUT), i18n("At least one FILE must be present"));
    if (!std::all_of(fileNames.cbegin(), fileNames.cend(), is_file()))
        throw Exception(makeError(GPG_ERR_INV_ARG), i18n("DECRYPT/VERIFY_FILES cannot use directories as input"));
}

void DecryptVerifyCommandFilesBase::doCanceled()
{
    if (d->controller) {
        d->controller->cancel();
    }
}

void DecryptVerifyCommandFilesBase::Private::slotProgress(const QString &what, int current, int total)
{
    Q_UNUSED(what)
    Q_UNUSED(current)
    Q_UNUSED(total)
    // ### FIXME report progress, via sendStatus()
}

void DecryptVerifyCommandFilesBase::Private::verificationResult(const VerificationResult &vResult)
{
    try {
        const std::vector<Signature> sigs = vResult.signatures();
        for (const Signature &sig : sigs) {
            const QString s = signatureToString(sig, sig.key(true, true));
            const char *color = summaryToString(sig.summary());
            q->sendStatusEncoded("SIGSTATUS", color + (' ' + hexencode(s.toUtf8().constData())));
        }
    } catch (...) {
    }
}

#include "decryptverifycommandfilesbase.moc"
