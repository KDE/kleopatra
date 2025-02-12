/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <selftest/selftest.h>

#include <gpgme++/global.h>

#include <QString>

namespace Kleo
{
namespace _detail
{

class SelfTestImplementation : public SelfTest
{
public:
    explicit SelfTestImplementation(const QString &name);
    ~SelfTestImplementation() override;

    QString name() const override
    {
        return m_name;
    }
    QString shortError() const override
    {
        return m_error;
    }
    QString longError() const override
    {
        return m_explanation;
    }
    QString proposedFix() const override
    {
        return m_proposedFix;
    }

    bool skipped() const override
    {
        return m_skipped;
    }
    bool passed() const override
    {
        return m_passed;
    }

protected:
    bool ensureEngineVersion(GpgME::Engine, int major, int minor, int patch);

protected:
    const QString m_name;
    QString m_error;
    QString m_explanation;
    QString m_proposedFix;
    bool m_skipped : 1;
    bool m_passed : 1;
};

}
}
