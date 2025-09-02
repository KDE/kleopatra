/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

class QByteArray;
class QUrl;
class QWidget;

namespace Kleo
{
class KeyParameters;

void saveCSR(const QByteArray &request, const KeyParameters &parameters, QWidget *parent);
}
