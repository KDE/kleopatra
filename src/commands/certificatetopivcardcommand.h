/*  commands/certificatetopivcardcommand.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/cardcommand.h>

namespace GpgME
{
class Error;
}

namespace Kleo
{
namespace Commands
{

class CertificateToPIVCardCommand : public CardCommand
{
    Q_OBJECT
public:
    CertificateToPIVCardCommand(const std::string &cardSlot, const std::string &serialno, QWidget *parent = nullptr);
    ~CertificateToPIVCardCommand() override;

public Q_SLOTS:
    void certificateToPIVCardDone(const GpgME::Error &err);

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
