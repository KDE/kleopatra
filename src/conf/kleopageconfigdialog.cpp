/*
    kleopageconfigdialog.cpp

    This file is part of Kleopatra
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-only

    It is derived from KCMultidialog which is:

    SPDX-FileCopyrightText: 2000 Matthias Elter <elter@kde.org>
    SPDX-FileCopyrightText: 2003 Daniel Molkentin <molkentin@kde.org>
    SPDX-FileCopyrightText: 2003, 2006 Matthias Kretz <kretz@kde.org>
    SPDX-FileCopyrightText: 2004 Frans Englich <frans.englich@telia.com>
    SPDX-FileCopyrightText: 2006 Tobias Koenig <tokoe@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "kleopageconfigdialog.h"

#include "kleoconfigmodule.h"

#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QLocale>
#include <QProcess>
#include <QPushButton>
#include <QUrl>

#include <KLocalizedString>
#include <KMessageBox>
#include <KStandardGuiItem>

#include "kleopatra_debug.h"

using namespace Kleo::Config;

KleoPageConfigDialog::KleoPageConfigDialog(QWidget *parent)
    : KPageDialog(parent)
{
    setModal(false);

    QDialogButtonBox *buttonBox = new QDialogButtonBox(this);
    buttonBox->setStandardButtons(QDialogButtonBox::Help //
                                  | QDialogButtonBox::RestoreDefaults //
                                  | QDialogButtonBox::Cancel //
                                  | QDialogButtonBox::Apply //
                                  | QDialogButtonBox::Ok //
                                  | QDialogButtonBox::Reset);
    KGuiItem::assign(buttonBox->button(QDialogButtonBox::Ok), KStandardGuiItem::ok());
    KGuiItem::assign(buttonBox->button(QDialogButtonBox::Cancel), KStandardGuiItem::cancel());
    KGuiItem::assign(buttonBox->button(QDialogButtonBox::RestoreDefaults), KStandardGuiItem::defaults());
    KGuiItem::assign(buttonBox->button(QDialogButtonBox::Apply), KStandardGuiItem::apply());
    KGuiItem::assign(buttonBox->button(QDialogButtonBox::Reset), KStandardGuiItem::reset());
    KGuiItem::assign(buttonBox->button(QDialogButtonBox::Help), KStandardGuiItem::help());
    buttonBox->button(QDialogButtonBox::Reset)->setEnabled(false);
    buttonBox->button(QDialogButtonBox::Apply)->setEnabled(false);

    connect(buttonBox->button(QDialogButtonBox::Apply), &QAbstractButton::clicked, this, &KleoPageConfigDialog::slotApplyClicked);
    connect(buttonBox->button(QDialogButtonBox::Ok), &QAbstractButton::clicked, this, &KleoPageConfigDialog::slotOkClicked);
    connect(buttonBox->button(QDialogButtonBox::RestoreDefaults), &QAbstractButton::clicked, this, &KleoPageConfigDialog::slotDefaultClicked);
    connect(buttonBox->button(QDialogButtonBox::Help), &QAbstractButton::clicked, this, &KleoPageConfigDialog::slotHelpClicked);
    connect(buttonBox->button(QDialogButtonBox::Reset), &QAbstractButton::clicked, this, &KleoPageConfigDialog::slotUser1Clicked);

    setButtonBox(buttonBox);

    connect(this, &KPageDialog::currentPageChanged, this, &KleoPageConfigDialog::slotCurrentPageChanged);
}

void KleoPageConfigDialog::slotCurrentPageChanged(KPageWidgetItem *current, KPageWidgetItem *previous)
{
    if (!previous) {
        return;
    }
    blockSignals(true);
    setCurrentPage(previous);

    auto previousModule = qobject_cast<KleoConfigModule *>(previous->widget());
    bool canceled = false;
    if (previousModule && mChangedModules.contains(previousModule)) {
        const int queryUser = KMessageBox::warningTwoActionsCancel(this,
                                                                   i18n("The settings of the current module have changed.\n"
                                                                        "Do you want to apply the changes or discard them?"),
                                                                   i18nc("@title:window", "Apply Settings"),
                                                                   KStandardGuiItem::apply(),
                                                                   KStandardGuiItem::discard(),
                                                                   KStandardGuiItem::cancel());
        if (queryUser == KMessageBox::ButtonCode::PrimaryAction) {
            previousModule->save();
        } else if (queryUser == KMessageBox::ButtonCode::SecondaryAction) {
            previousModule->load();
        }
        canceled = queryUser == KMessageBox::Cancel;
    }
    if (!canceled) {
        mChangedModules.remove(previousModule);
        setCurrentPage(current);
    }
    blockSignals(false);

    clientChanged();
}

void KleoPageConfigDialog::apply()
{
    QPushButton *applyButton = buttonBox()->button(QDialogButtonBox::Apply);
    applyButton->setFocus();
    for (const auto &module : mChangedModules) {
        module->save();
    }
    mChangedModules.clear();
    Q_EMIT configCommitted();
    clientChanged();
}

void KleoPageConfigDialog::slotDefaultClicked()
{
    const KPageWidgetItem *item = currentPage();
    if (!item) {
        return;
    }

    auto module = qobject_cast<KleoConfigModule *>(item->widget());
    if (!module) {
        return;
    }
    module->defaults();
    clientChanged();
}

void KleoPageConfigDialog::slotUser1Clicked()
{
    const KPageWidgetItem *item = currentPage();
    if (!item) {
        return;
    }

    auto module = qobject_cast<KleoConfigModule *>(item->widget());
    if (!module) {
        return;
    }
    module->load();
    mChangedModules.remove(module);
    clientChanged();
}

void KleoPageConfigDialog::slotApplyClicked()
{
    apply();
}

void KleoPageConfigDialog::slotOkClicked()
{
    apply();
    accept();
}

void KleoPageConfigDialog::slotHelpClicked()
{
    const KPageWidgetItem *item = currentPage();
    if (!item) {
        return;
    }

    const QString docPath = mHelpUrls.value(item->name());
    QUrl docUrl;

#ifdef Q_OS_WIN
    docUrl =
        QUrl(QLatin1StringView("https://docs.kde.org/index.php?branch=stable5&language=") + QLocale().name() + QLatin1StringView("&application=kleopatra"));
#else
    docUrl = QUrl(QStringLiteral("help:/")).resolved(QUrl(docPath)); // same code as in KHelpClient::invokeHelp
#endif
    if (docUrl.scheme() == QLatin1StringView("help") || docUrl.scheme() == QLatin1StringView("man") || docUrl.scheme() == QLatin1StringView("info")) {
        // Warning: Don't assume that the program needs to be in PATH. On Windows, it will also be found next to the calling process.
        QProcess::startDetached(QStringLiteral("khelpcenter"), QStringList() << docUrl.toString());
    } else {
        QDesktopServices::openUrl(docUrl);
    }
}

void KleoPageConfigDialog::addModule(const QString &name, const QString &docPath, const QString &icon, KleoConfigModule *module)
{
    mModules << module;
    module->load();
    auto item = addPage(module, name);
    item->setIcon(QIcon::fromTheme(icon));
    connect(module, &KleoConfigModule::changed, this, [this, module]() {
        moduleChanged(true);
        mChangedModules.insert(module);
    });
    mHelpUrls.insert(name, docPath);
}

void KleoPageConfigDialog::moduleChanged(bool state)
{
    auto module = qobject_cast<KleoConfigModule *>(sender());
    qCDebug(KLEOPATRA_LOG) << "Module changed: " << state << " mod " << module;
    if (mChangedModules.contains(module)) {
        if (!state) {
            mChangedModules.remove(module);
        } else {
            return;
        }
    }
    if (state) {
        mChangedModules << module;
    }
    clientChanged();
}

void KleoPageConfigDialog::clientChanged()
{
    const KPageWidgetItem *item = currentPage();
    if (!item) {
        return;
    }
    auto module = qobject_cast<KleoConfigModule *>(currentPage()->widget());

    if (!module) {
        return;
    }
    qCDebug(KLEOPATRA_LOG) << "Client changed: "
                           << " mod " << module;

    bool change = mChangedModules.contains(module);

    QPushButton *resetButton = buttonBox()->button(QDialogButtonBox::Reset);
    if (resetButton) {
        resetButton->setEnabled(change);
    }

    QPushButton *applyButton = buttonBox()->button(QDialogButtonBox::Apply);
    if (applyButton) {
        applyButton->setEnabled(change);
    }
}

#include "moc_kleopageconfigdialog.cpp"
