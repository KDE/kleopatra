/* -*- mode: c++; c-basic-offset:4 -*-
    smartcard/readerstatus.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QMetaType>
#include <QObject>

#include "card.h"

#include <gpgme++/global.h>

#include <memory>
#include <vector>

namespace GpgME
{
class AssuanTransaction;
class Context;
class Error;
}

namespace Kleo
{
namespace SmartCard
{

class ReaderStatus : public QObject
{
    Q_OBJECT
public:
    enum Action {
        NoAction,
        UpdateCards,
        LearnCards,
    };

    explicit ReaderStatus(QObject *parent = nullptr);
    ~ReaderStatus() override;

    static const ReaderStatus *instance();
    static ReaderStatus *mutableInstance();

    Action currentAction() const;

    using TransactionFunc = std::function<void(const GpgME::Error &)>;
    void startSimpleTransaction(const std::shared_ptr<Card> &card, const QByteArray &cmd, QObject *receiver, const TransactionFunc &slot);
    void startTransaction(const std::shared_ptr<Card> &card,
                          const QByteArray &cmd,
                          QObject *receiver,
                          const TransactionFunc &slot,
                          std::unique_ptr<GpgME::AssuanTransaction> transaction);

    Card::Status cardStatus(unsigned int slot) const;
    std::string firstCardWithNullPin() const;

    std::vector<std::shared_ptr<Card>> getCards() const;

    std::shared_ptr<Card> getCard(const std::string &serialNumber, const std::string &appName) const;
    std::shared_ptr<Card> getCardWithKeyRef(const std::string &serialNumber, const std::string &keyRef) const;

    template<typename T>
    std::shared_ptr<T> getCard(const std::string &serialNumber) const
    {
        return std::dynamic_pointer_cast<T>(getCard(serialNumber, T::AppName));
    }

    static std::string switchCard(std::shared_ptr<GpgME::Context> &ctx, const std::string &serialNumber, GpgME::Error &err);
    static std::string switchApp(std::shared_ptr<GpgME::Context> &ctx, const std::string &serialNumber, const std::string &appName, GpgME::Error &err);
    static GpgME::Error switchCardAndApp(const std::string &serialNumber, const std::string &appName);
    static GpgME::Error switchCardBackToOpenPGPApp(const std::string &serialNumber);

public Q_SLOTS:
    void updateStatus();
    void updateCard(const std::string &serialNumber, const std::string &appName);
    void learnCards(GpgME::Protocol protocol);
    void startMonitoring();

Q_SIGNALS:
    void firstCardWithNullPinChanged(const std::string &serialNumber);
    void cardAdded(const std::string &serialNumber, const std::string &appName);
    void cardChanged(const std::string &serialNumber, const std::string &appName);
    void cardRemoved(const std::string &serialNumber, const std::string &appName);
    void currentActionChanged(Action action);
    void updateCardsStarted();
    void updateCardStarted(const std::string &serialNumber, const std::string &appName);
    void updateFinished();
    void startingLearnCards(GpgME::Protocol protocol);
    void cardsLearned(GpgME::Protocol protocol);
    void startOfGpgAgentRequested();

private:
    void setCurrentAction(Action action);
    void onUpdateCardsStarted();
    void onUpdateCardStarted(const std::string &serialNumber, const std::string &appName);
    void onUpdateFinished();
    void onStartingLearnCards(GpgME::Protocol protocol);
    void onCardsLearned(GpgME::Protocol protocol);

    class Private;
    std::shared_ptr<Private> d;
};

} // namespace SmartCard
} // namespace Kleo

Q_DECLARE_METATYPE(Kleo::SmartCard::Card::Status)
