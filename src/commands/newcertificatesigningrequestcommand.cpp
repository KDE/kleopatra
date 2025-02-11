/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "newcertificatesigningrequestcommand.h"

#include "command_p.h"

#include "newcertificatewizard/newcertificatewizard.h"

#include <settings.h>

#include <kleopatra_debug.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

class NewCertificateSigningRequestCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::NewCertificateSigningRequestCommand;
    NewCertificateSigningRequestCommand *q_func() const
    {
        return static_cast<NewCertificateSigningRequestCommand *>(q);
    }

public:
    explicit Private(NewCertificateSigningRequestCommand *qq, KeyListController *c)
        : Command::Private{qq, c}
    {
    }

    void createCSR();

private:
    void slotDialogAccepted();

private:
    QPointer<NewCertificateWizard> dialog;
};

NewCertificateSigningRequestCommand::Private *NewCertificateSigningRequestCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const NewCertificateSigningRequestCommand::Private *NewCertificateSigningRequestCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

void NewCertificateSigningRequestCommand::Private::createCSR()
{
    Q_ASSERT(!dialog);

    dialog = new NewCertificateWizard;
    applyWindowID(dialog);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        canceled();
    });

    dialog->setProtocol(GpgME::CMS);
    dialog->show();
}

void NewCertificateSigningRequestCommand::Private::slotDialogAccepted()
{
    finished();
}

NewCertificateSigningRequestCommand::NewCertificateSigningRequestCommand()
    : NewCertificateSigningRequestCommand(nullptr, nullptr)
{
}

NewCertificateSigningRequestCommand::NewCertificateSigningRequestCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
}

NewCertificateSigningRequestCommand::~NewCertificateSigningRequestCommand() = default;

void NewCertificateSigningRequestCommand::doStart()
{
    const Kleo::Settings settings{};
    if (settings.cmsEnabled() && settings.cmsCertificateCreationAllowed()) {
        d->createCSR();
    } else {
        d->error(i18n("You are not allowed to create S/MIME certificate signing requests."));
        d->finished();
    }
}

void NewCertificateSigningRequestCommand::doCancel()
{
    if (d->dialog) {
        d->dialog->close();
    }
}

#undef d
#undef q

#include "moc_newcertificatesigningrequestcommand.cpp"
