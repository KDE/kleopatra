/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "cryptouihelpers.h"

#include <Libkleo/Compliance>

#include <KGuiItem>
#include <KLocalizedString>
#include <KMessageBox>
#include <KStandardGuiItem>

#include <QDialog>
#include <QDialogButtonBox>
#include <QIcon>

using namespace Qt::StringLiterals;

bool Kleo::retryEncryptionWithLowerSecurity(QWidget *parent, const QString &originalButtonText)
{
    auto dialog = new QDialog{parent};
    dialog->setWindowTitle(i18nc("@title:window", "Retry with Lower Security?"));

    QString msg = u"<p>"_s + i18nc("@info", "Encryption failed because at least one certificate could not be validated.") + u"</p>"_s;
    msg += u"<p>"_s + i18nc("@info", "You can retry the operation with fewer validity checks on the certificates.") + u"</p>"_s;

    const QString retryButtonText = i18nc("@action:button Sign / Encrypt (not Compliant)",
                                          "%1 (%2)",
                                          originalButtonText,
                                          DeVSCompliance::isActive() ? DeVSCompliance::name(false) : i18nc("@action:button", "with Lower Security"));
    auto buttonBox = new QDialogButtonBox{dialog};
    buttonBox->setStandardButtons(QDialogButtonBox::Retry | QDialogButtonBox::Cancel);
    auto retryButton = buttonBox->button(QDialogButtonBox::Retry);
    KGuiItem::assign(retryButton, KGuiItem{retryButtonText, QIcon::fromTheme(u"security-medium"_s), u""_s});
    KGuiItem::assign(buttonBox->button(QDialogButtonBox::Cancel), KStandardGuiItem::cancel());

    if (DeVSCompliance::isActive()) {
        msg += u"<p>"_s + i18nc("@info", "WARNING: Compliance of the result: %1", DeVSCompliance::name(false)) + u"</p>"_s;
        DeVSCompliance::decorate(retryButton, false);
    }

    // in compliance mode make it harder to retry with lower security
    const KMessageBox::Options options = DeVSCompliance::isActive() ? KMessageBox::Notify | KMessageBox::Dangerous : KMessageBox::Notify;
    const int answer = KMessageBox::createKMessageBox(dialog, buttonBox, QMessageBox::Question, msg, QStringList{}, QString{}, nullptr, options);

    return answer == QDialogButtonBox::Retry;
}
