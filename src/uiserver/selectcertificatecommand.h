/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"
#include <QObject>

namespace Kleo
{

class SelectCertificateCommand : public QObject, public AssuanCommandMixin<SelectCertificateCommand>
{
    Q_OBJECT
public:
    SelectCertificateCommand();
    ~SelectCertificateCommand() override;

    static const char *staticName()
    {
        return "SELECT_CERTIFICATE";
    }

private:
    int doStart() override;
    void doCanceled() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotSelectedCertificates(int, QByteArray))
    Q_PRIVATE_SLOT(d, void slotDialogAccepted())
    Q_PRIVATE_SLOT(d, void slotDialogRejected())
};

}
