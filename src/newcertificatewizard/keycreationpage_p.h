/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "wizardpage_p.h"

#include "utils/emptypassphraseprovider.h"

#include <QPointer>

namespace GpgME
{
class KeyGenerationResult;
}
namespace QGpgME
{
class KeyGenerationJob;
}
namespace Kleo
{
class KeyUsage;
}

class KeyCreationPage : public Kleo::NewCertificateUi::WizardPage
{
    Q_OBJECT
public:
    explicit KeyCreationPage(QWidget *p = nullptr);
    ~KeyCreationPage() override;

    bool isComplete() const override;

    void initializePage() override;

private:
    void startJob();
    Kleo::KeyUsage keyUsage() const;
    QString createGnupgKeyParms() const;

private Q_SLOTS:
    void slotResult(const GpgME::KeyGenerationResult &result, const QByteArray &request, const QString &auditLog);

private:
    struct UI;
    std::unique_ptr<UI> ui;

    EmptyPassphraseProvider mEmptyPassphraseProvider;
    QPointer<QGpgME::KeyGenerationJob> job;
};
