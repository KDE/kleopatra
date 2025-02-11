/* -*- mode: c++; c-basic-offset:4 -*-
    This clipboard is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "importcertificatescommand.h"

#ifndef QT_NO_CLIPBOARD

namespace Kleo
{

class ImportCertificateFromClipboardCommand : public ImportCertificatesCommand
{
    Q_OBJECT
public:
    explicit ImportCertificateFromClipboardCommand(KeyListController *parent);
    explicit ImportCertificateFromClipboardCommand(QAbstractItemView *view, KeyListController *parent);
    ~ImportCertificateFromClipboardCommand() override;

    static bool canImportCurrentClipboard();

private:
    void doStart() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};
}

#endif // QT_NO_CLIPBOARD
