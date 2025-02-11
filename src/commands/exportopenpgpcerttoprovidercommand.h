/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 Felix Tiede

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

#include <QPointer>

#include <gpgme++/key.h>

namespace QGpgME
{
class WKSPublishJob;
}

namespace Kleo
{
namespace Commands
{

class ExportOpenPGPCertToProviderCommand : public Command
{
    Q_OBJECT
public:
    explicit ExportOpenPGPCertToProviderCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ExportOpenPGPCertToProviderCommand(const GpgME::UserID &uid);

    ~ExportOpenPGPCertToProviderCommand() override;

    static Restrictions restrictions()
    {
        return OnlyOneKey | NeedSecretKey | MustBeOpenPGP;
    }

private Q_SLOTS:
    void wksJobResult(const GpgME::Error &, const QByteArray &, const QByteArray &);

private:
    void doStart() override;
    void doCancel() override;

    QString senderAddress() const;

private:
    GpgME::UserID uid;
    QPointer<QGpgME::WKSPublishJob> wksJob;
};

}
}
