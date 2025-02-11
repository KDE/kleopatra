/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "cached.h"
#include "input.h"

#include <KLocalizedString>
#include <QIODevice>
#include <QString>

namespace Kleo
{

class InputImplBase : public Input
{
public:
    InputImplBase()
        : Input()
        , m_customLabel()
        , m_defaultLabel()
    {
    }

    QString label() const override
    {
        return m_customLabel.isEmpty() ? m_defaultLabel : m_customLabel;
    }

    void setDefaultLabel(const QString &l)
    {
        m_defaultLabel = l;
    }

    void setLabel(const QString &l) override
    {
        m_customLabel = l;
    }

    QString errorString() const override
    {
        if (m_errorString.dirty()) {
            m_errorString = doErrorString();
        }
        return m_errorString;
    }

private:
    virtual QString doErrorString() const
    {
        if (const std::shared_ptr<QIODevice> io = ioDevice()) {
            return io->errorString();
        } else {
            return i18n("No input device");
        }
    }

private:
    QString m_customLabel;
    QString m_defaultLabel;
    mutable cached<QString> m_errorString;
};

}
