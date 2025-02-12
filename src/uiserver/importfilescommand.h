/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"
#include <QObject>

namespace Kleo
{

class ImportFilesCommand : public QObject, public AssuanCommandMixin<ImportFilesCommand>
{
    Q_OBJECT
public:
    ImportFilesCommand();
    ~ImportFilesCommand() override;

    static const char *staticName()
    {
        return "IMPORT_FILES";
    }

private:
    int doStart() override;
    void doCanceled() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotCommandFinished())
    Q_PRIVATE_SLOT(d, void slotCommandCanceled())
};

}
