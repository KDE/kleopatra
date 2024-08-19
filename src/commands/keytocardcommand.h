/*  commands/keytocardcommand.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/cardcommand.h>

#include <gpgme++/key.h>

#include <memory>

namespace Kleo
{
namespace SmartCard
{
class Card;
}
}

namespace Kleo
{
namespace Commands
{

class KeyToCardCommand : public CardCommand
{
    Q_OBJECT
public:
    KeyToCardCommand(const GpgME::Subkey &subkey);
    KeyToCardCommand(const std::string &cardSlot, const std::string &serialNumber, const std::string &appName, QWidget *parent = nullptr);
    ~KeyToCardCommand() override;

    static std::vector<std::shared_ptr<Kleo::SmartCard::Card>> getSuitableCards(const GpgME::Subkey &subkey);

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

}
}
