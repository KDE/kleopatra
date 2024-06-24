/*  view/smartcardwidget.h

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

/* SmartCardWidget a generic widget to interact with smartcards */
class SmartCardWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SmartCardWidget(QWidget *parent = nullptr);
    ~SmartCardWidget() override;

    void createActions(KActionCollection *ac);

    void showCards(const std::vector<std::shared_ptr<Kleo::SmartCard::Card>> &cards);

public Q_SLOTS:
    void reload();

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace Kleo
