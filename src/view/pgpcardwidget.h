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

#include "commands/changepincommand.h"

#include <gpgme++/error.h>

#include <string>

class QLabel;

namespace Kleo
{
class GenCardKeyDialog;

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
    void doGenKey(GenCardKeyDialog *dlg);
    void genKeyDone(const GpgME::Error &err, const std::string &backup);

public Q_SLOTS:
    void genkeyRequested();
    void changeNameRequested();
    void changeNameResult(const GpgME::Error &err);
    void changeUrlRequested();
    void changeUrlResult(const GpgME::Error &err);

private:
    void doChangePin(const std::string &keyRef, Commands::ChangePinCommand::ChangePinMode mode = Commands::ChangePinCommand::NormalMode);

private:
    QLabel *mCardHolderLabel = nullptr;
    QLabel *mUrlLabel = nullptr;
    QString mUrl;
    bool mCardIsEmpty = false;
    bool mIs21 = false;
};
} // namespace Kleo
