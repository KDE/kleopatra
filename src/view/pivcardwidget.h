/*  view/pivcardwiget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "smartcardwidget.h"

#include <smartcard/keypairinfo.h>

#include <QMap>

#include <gpgme++/error.h>

class QLabel;
class QPushButton;

namespace Kleo
{

namespace SmartCard
{
class PIVCard;
} // namespace SmartCard

class PIVCardWidget : public SmartCardWidget
{
    Q_OBJECT
public:
    explicit PIVCardWidget(QWidget *parent = nullptr);
    ~PIVCardWidget() override;

    void setCard(const SmartCard::PIVCard *card);

    struct KeyWidgets {
        SmartCard::KeyPairInfo keyInfo;
        std::string certificateData;
        QLabel *keyGrip = nullptr;
        QLabel *keyAlgorithm = nullptr;
        QLabel *certificateInfo = nullptr;
        QPushButton *generateButton = nullptr;
        QPushButton *createCSRButton = nullptr;
        QPushButton *writeCertificateButton = nullptr;
        QPushButton *importCertificateButton = nullptr;
        QPushButton *writeKeyButton = nullptr;
    };

private:
    KeyWidgets createKeyWidgets(const SmartCard::KeyPairInfo &keyInfo);
    void updateCachedValues(const std::string &keyRef, const SmartCard::PIVCard *card);
    void updateKeyWidgets(const std::string &keyRef);
    void generateKey(const std::string &keyref);
    void createCSR(const std::string &keyref);
    void writeCertificateToCard(const std::string &keyref);
    void importCertificateFromCard(const std::string &keyref);
    void writeKeyToCard(const std::string &keyref);
    void createKeyFromCardKeys();
    void changePin(const std::string &keyRef);
    void setAdminKey();

private:
    QLabel *mSerialNumberLabel = nullptr;
    QLabel *mVersionLabel = nullptr;
    QPushButton *mKeyForCardKeysButton = nullptr;
    std::map<std::string, KeyWidgets> mKeyWidgets;
};
} // namespace Kleo
