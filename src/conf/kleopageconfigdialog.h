/*
    kleopageconfigdialog.h.h

    This file is part of Kleopatra
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-only
*/

#pragma once

#include <KPageDialog>
#include <QList>

class KPageWidgetItem;

namespace Kleo
{
namespace Config
{
class KleoConfigModule;
}
}

/**
 * KPageDialog based config dialog to be used when
 * KCMUtils are not available. */
class KleoPageConfigDialog : public KPageDialog
{
    Q_OBJECT
public:
    explicit KleoPageConfigDialog(QWidget *parent = nullptr);

    void addModule(const QString &name, const QString &docPath, const QString &icon, Kleo::Config::KleoConfigModule *module);

Q_SIGNALS:
    void configCommitted();

protected Q_SLOTS:
    void slotDefaultClicked();
    void slotUser1Clicked();
    void slotApplyClicked();
    void slotOkClicked();
    void slotHelpClicked();
    void slotCurrentPageChanged(KPageWidgetItem *current, KPageWidgetItem *previous);
    void moduleChanged(bool value);

private:
    void clientChanged();
    void apply();

    QList<Kleo::Config::KleoConfigModule *> mModules;
    QSet<Kleo::Config::KleoConfigModule *> mChangedModules;
    QMap<QString, QString> mHelpUrls;
};
