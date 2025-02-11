/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "encryptemailwizard.h"

#include <settings.h>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

EncryptEMailWizard::EncryptEMailWizard(QWidget *parent, Qt::WindowFlags flags)
    : SignEncryptWizard(parent, flags)
{
    setWindowTitle(i18nc("@title:window", "Encrypt Text"));
    std::vector<int> pageOrder;
    pageOrder.push_back(Page::ResolveRecipients);
    pageOrder.push_back(Page::Result);
    setPageOrder(pageOrder);
    setCommitPage(Page::ResolveRecipients);

    setKeepResultPageOpenWhenDone(Kleo::Settings{}.showResultsAfterEncryptingClipboard());
}

EncryptEMailWizard::~EncryptEMailWizard()
{
    // always save the setting even if the dialog was canceled (the dialog's result
    // is always Rejected because the result page has no Finish button)
    Kleo::Settings settings;
    settings.setShowResultsAfterEncryptingClipboard(keepResultPageOpenWhenDone());
    settings.save();
}

#include "moc_encryptemailwizard.cpp"
