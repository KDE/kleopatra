/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

class QString;

namespace Kleo
{

class SelfTest
{
public:
    virtual ~SelfTest();

    virtual QString name() const = 0;
    virtual QString shortError() const = 0;
    virtual QString longError() const = 0;
    virtual QString proposedFix() const = 0;

    virtual bool passed() const = 0;
    virtual bool skipped() const = 0;
    virtual bool canFixAutomatically() const;
    virtual bool fix();

    bool failed() const
    {
        return !skipped() && !passed();
    }
};

}
