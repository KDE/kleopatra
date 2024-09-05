/*  view/smartcardswidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QWidget>

#include <memory>
#include <vector>

class KActionCollection;

namespace Kleo
{
namespace SmartCard
{
class Card;
}

/* SmartCardsWidget a generic widget to interact with smartcards */
class SmartCardsWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SmartCardsWidget(QWidget *parent = nullptr);
    ~SmartCardsWidget() override;

    void showCards(const std::vector<std::shared_ptr<Kleo::SmartCard::Card>> &cards);

public Q_SLOTS:
    void reload();

Q_SIGNALS:
    void statusMessage(const QString &message, const QByteArray &cardId);
    void cardChanged(const QByteArray &cardId);

private:
    void updateReloadButton();

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace Kleo
