/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "selftest.h"

#include "implementation_p.h"

using namespace Kleo;
using namespace Kleo::_detail;

SelfTest::~SelfTest()
{
}

bool SelfTest::canFixAutomatically() const
{
    return false;
}
bool SelfTest::fix()
{
    return false;
}

SelfTestImplementation::SelfTestImplementation(const QString &title)
    : SelfTest()
    , m_name(title)
    , m_error()
    , m_explanation()
    , m_proposedFix()
    , m_skipped(false)
    , m_passed(false)
{
}

SelfTestImplementation::~SelfTestImplementation()
{
}

// bool SelfTestImplementation::ensureEngineVersion( GpgME::Engine engine, int major, int minor, int patch )
// in enginecheck.cpp, since it reuses the instrumentation there
