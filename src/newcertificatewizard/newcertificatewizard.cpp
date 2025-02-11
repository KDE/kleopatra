/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "newcertificatewizard.h"

#include "enterdetailspage_p.h"
#include "keycreationpage_p.h"
#include "resultpage_p.h"

#include <KLocalizedString>

#include <QDir>
#include <QTemporaryDir>

using namespace Kleo;
using namespace Kleo::NewCertificateUi;
using namespace GpgME;

class NewCertificateWizard::Private
{
    friend class ::Kleo::NewCertificateWizard;
    NewCertificateWizard *const q;

public:
    explicit Private(NewCertificateWizard *qq)
        : q(qq)
        , tmp(QDir::temp().absoluteFilePath(QStringLiteral("kleo-")))
        , ui(q)
    {
        q->setWindowTitle(i18nc("@title:window", "Key Pair Creation Wizard"));
    }

private:
    GpgME::Protocol protocol = GpgME::UnknownProtocol;
    QTemporaryDir tmp;
    struct Ui {
        EnterDetailsPage enterDetailsPage;
        KeyCreationPage keyCreationPage;
        ResultPage resultPage;

        explicit Ui(NewCertificateWizard *q)
            : enterDetailsPage(q)
            , keyCreationPage(q)
            , resultPage(q)
        {
            Q_SET_OBJECT_NAME(enterDetailsPage);
            Q_SET_OBJECT_NAME(keyCreationPage);
            Q_SET_OBJECT_NAME(resultPage);

            q->setOptions(NoBackButtonOnStartPage | DisabledBackButtonOnLastPage);

            q->setPage(EnterDetailsPageId, &enterDetailsPage);
            q->setPage(KeyCreationPageId, &keyCreationPage);
            q->setPage(ResultPageId, &resultPage);
        }

    } ui;
};

NewCertificateWizard::NewCertificateWizard(QWidget *p)
    : QWizard(p)
    , d(new Private(this))
{
}

NewCertificateWizard::~NewCertificateWizard()
{
}

void NewCertificateWizard::showEvent(QShowEvent *event)
{
    // set WA_KeyboardFocusChange attribute to force visual focus of the
    // focussed button when the wizard is shown (required for Breeze style
    // and some other styles)
    window()->setAttribute(Qt::WA_KeyboardFocusChange);
    QWizard::showEvent(event);
}

void NewCertificateWizard::setProtocol(Protocol proto)
{
    d->protocol = proto;
}

Protocol NewCertificateWizard::protocol() const
{
    return d->protocol;
}

void NewCertificateWizard::restartAtEnterDetailsPage()
{
    restart();
    while (currentId() != NewCertificateWizard::EnterDetailsPageId) {
        next();
    }
}

QDir NewCertificateWizard::tmpDir() const
{
    return QDir(d->tmp.path());
}

#include "moc_newcertificatewizard.cpp"
