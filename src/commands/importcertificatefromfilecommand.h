/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "importcertificatescommand.h"

#include <QStringList>

namespace Kleo
{

class ImportCertificateFromFileCommand : public ImportCertificatesCommand
{
    Q_OBJECT
public:
    explicit ImportCertificateFromFileCommand();
    explicit ImportCertificateFromFileCommand(KeyListController *parent);
    explicit ImportCertificateFromFileCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ImportCertificateFromFileCommand(const QStringList &files, KeyListController *parent);
    explicit ImportCertificateFromFileCommand(const QStringList &files, QAbstractItemView *view, KeyListController *parent);
    ~ImportCertificateFromFileCommand() override;

    void setFiles(const QStringList &files);
    QStringList files() const;

private:
    void doStart() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};
}
