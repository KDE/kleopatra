/*  view/pgpcardwiget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "smartcardwidget.h"

#include <string>

class QLabel;

namespace GpgME
{
class Error;
}

namespace Kleo
{
namespace SmartCard
{
class OpenPGPCard;
} // namespace SmartCard

class PGPCardWidget : public SmartCardWidget
{
    Q_OBJECT
public:
    explicit PGPCardWidget(QWidget *parent = nullptr);

    void setCard(const SmartCard::OpenPGPCard *card);

public Q_SLOTS:
    void changeNameRequested();
    void changeNameResult(const GpgME::Error &err);
    void changeUrlRequested();
    void changeUrlResult(const GpgME::Error &err);

private:
    QLabel *mCardHolderLabel = nullptr;
    QLabel *mUrlLabel = nullptr;
    QString mUrl;
};
} // namespace Kleo
