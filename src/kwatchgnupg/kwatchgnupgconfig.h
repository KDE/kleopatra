/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004, 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

class QCheckBox;
class QDialogButtonBox;
class QSpinBox;

class KWatchGnuPGConfig : public QDialog
{
    Q_OBJECT
public:
    explicit KWatchGnuPGConfig(QWidget *parent = nullptr);
    ~KWatchGnuPGConfig() override;

    void loadConfig();
    void saveConfig();

Q_SIGNALS:
    void reconfigure();

private Q_SLOTS:
    void slotChanged();
    void slotSave();
    void slotSetHistorySizeUnlimited();

private:
    QSpinBox *mLoglenSB = nullptr;
    QDialogButtonBox *mButtonBox = nullptr;
};
