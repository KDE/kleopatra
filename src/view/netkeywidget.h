/*  view/netkeywidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "smartcardwidget.h"

#include <Libkleo/Predicates>

#include <gpgme++/error.h>

#include <set>
#include <string>
#include <vector>

class QLabel;
class QPushButton;

namespace Kleo
{
class NullPinWidget;

namespace SmartCard
{
class NetKeyCard;
}

class NetKeyWidget : public SmartCardWidget
{
    Q_OBJECT
public:
    explicit NetKeyWidget(QWidget *parent = nullptr);
    ~NetKeyWidget() override;

    void setCard(const SmartCard::NetKeyCard *card);

private:
    void doChangePin(const std::string &keyRef);
    void createKeyFromCardKeys();
    void createCSR();

private:
    QLabel *mErrorLabel = nullptr;
    NullPinWidget *mNullPinWidget = nullptr;
    QPushButton *mKeyForCardKeysButton = nullptr;
    QPushButton *mCreateCSRButton = nullptr;
    QPushButton *mChangeNKSPINBtn = nullptr;
    QPushButton *mChangeSigGPINBtn = nullptr;
};
} // namespace Kleo
