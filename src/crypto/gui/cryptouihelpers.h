/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

class QString;
class QWidget;

namespace Kleo
{
bool retryEncryptionWithLowerSecurity(QWidget *parent, const QString &originalButtonText);
}
