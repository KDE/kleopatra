/*  view/smartcardwidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

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
    void addCardKeysView();

public:
    ~SmartCardWidget() override;

    void setCard(const Kleo::SmartCard::Card *card);
    const Kleo::SmartCard::Card *card() const;

    Kleo::SmartCard::AppType cardType() const;
    std::string serialNumber() const;
    std::string currentCardSlot() const;
    GpgME::Key currentCertificate() const;

protected:
    KMessageWidget *nullPinMessageWidget() const;
    QLabel *statusLabel() const;

protected:
    QVBoxLayout *mContentLayout = nullptr;
    QGridLayout *mInfoGridLayout = nullptr;

private:
    Kleo::SmartCard::AppType mAppType;
    std::shared_ptr<const Kleo::SmartCard::Card> mCard;

    std::unique_ptr<Kleo::InfoField> mCardTypeField;
    std::unique_ptr<Kleo::InfoField> mSerialNumberField;
    std::unique_ptr<Kleo::InfoField> mCardholderField;
    std::unique_ptr<Kleo::InfoField> mPublicKeyUrlField;
    std::unique_ptr<Kleo::InfoField> mPinCountersField;
    QToolButton *mCardActionsButton = nullptr;
    KMessageWidget *mNullPinWidget = nullptr;
    QLabel *mStatusLabel = nullptr;
    KMessageWidget *mErrorWidget = nullptr;
    Kleo::CardKeysView *mCardKeysView = nullptr;
};
