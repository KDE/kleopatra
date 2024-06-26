// This file is part of the KDE libraries
// SPDX-FileCopyrightText: 2012 David Faure <faure+bluesystems@kde.org>
// SPDX-License-Identifier: LGPL-2.0-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <KMessageBoxDontAskAgainInterface>

class KMessageBoxDontAskAgainConfigStorage : public KMessageBoxDontAskAgainInterface
{
public:
    KMessageBoxDontAskAgainConfigStorage()
        : KMessageBox_againConfig(nullptr)
    {
    }
    ~KMessageBoxDontAskAgainConfigStorage() override
    {
    }

    bool shouldBeShownTwoActions(const QString &dontShowAgainName, KMessageBox::ButtonCode &result) override;
    bool shouldBeShownContinue(const QString &dontShowAgainName) override;
    void saveDontShowAgainTwoActions(const QString &dontShowAgainName, KMessageBox::ButtonCode result) override;
    void saveDontShowAgainContinue(const QString &dontShowAgainName) override;
    void enableAllMessages() override;
    void enableMessage(const QString &dontShowAgainName) override;
    void setConfig(KConfig *cfg) override
    {
        KMessageBox_againConfig = cfg;
    }

private:
    KConfig *KMessageBox_againConfig;
};