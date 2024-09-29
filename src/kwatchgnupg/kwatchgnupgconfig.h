/*
    kwatchgnupgconfig.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004, 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

class QCheckBox;
class QComboBox;
class QDialogButtonBox;
class QSpinBox;
namespace Kleo
{
class FileNameRequester;
}

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
    Kleo::FileNameRequester *mExeED;
    Kleo::FileNameRequester *mSocketED;
    QComboBox *mLogLevelCB;
    QSpinBox *mLoglenSB;
    QCheckBox *mWordWrapCB;
    QDialogButtonBox *mButtonBox;
};
