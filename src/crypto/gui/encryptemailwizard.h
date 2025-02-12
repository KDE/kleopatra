/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/gui/signencryptwizard.h>

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class EncryptEMailWizard : public SignEncryptWizard
{
    Q_OBJECT
public:
    explicit EncryptEMailWizard(QWidget *parent = nullptr, Qt::WindowFlags flags = {});
    ~EncryptEMailWizard() override;
};

}
}
}
