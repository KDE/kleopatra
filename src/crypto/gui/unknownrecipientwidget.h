/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QString>
#include <QWidget>

namespace Kleo
{
class UnknownRecipientWidget : public QWidget
{
    Q_OBJECT
public:
    explicit UnknownRecipientWidget(const char *keyid, QWidget *parent = nullptr);

    QString keyID() const;

private:
    QString mKeyID;
};

} // namespace Kleo:
