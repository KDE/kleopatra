/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QPointer>
#include <QWidget>

#include <memory>
#include <string>

class KMessageWidget;
class QGridLayout;
class QLabel;
class QToolButton;
class QVBoxLayout;

namespace GpgME
{
class Key;
}
namespace QGpgME
{
class Job;
}

namespace Kleo
{
class CardKeysView;
class InfoField;
}
namespace Kleo::SmartCard
{
enum class AppType;
class Card;
}

class SmartCardWidget : public QWidget
{
    Q_OBJECT
protected:
    SmartCardWidget(Kleo::SmartCard::AppType appType, QWidget *parent = nullptr);

public:
    ~SmartCardWidget() override;

    void setCard(const Kleo::SmartCard::Card *card);
    const Kleo::SmartCard::Card *card() const;

    Kleo::SmartCard::AppType cardType() const;
    std::string serialNumber() const;
    std::string currentCardSlot() const;
    GpgME::Key currentCertificate() const;

Q_SIGNALS:
    void statusMessage(const QString &message);

private:
    void retrieveOpenPGPCertificate();

private:
    Kleo::SmartCard::AppType mAppType;
    std::shared_ptr<const Kleo::SmartCard::Card> mCard;
    QPointer<QGpgME::Job> mJob;

    std::unique_ptr<Kleo::InfoField> mCardTypeField;
    std::unique_ptr<Kleo::InfoField> mSerialNumberField;
    std::unique_ptr<Kleo::InfoField> mCardholderField;
    std::unique_ptr<Kleo::InfoField> mPublicKeyUrlField;
    std::unique_ptr<Kleo::InfoField> mPinCountersField;
    QToolButton *mCardActionsButton = nullptr;
    KMessageWidget *mNullPinWidget = nullptr;
    KMessageWidget *mErrorWidget = nullptr;
    Kleo::CardKeysView *mCardKeysView = nullptr;
};
