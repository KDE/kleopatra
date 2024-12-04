// SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
// SPDX-FileContributor: Intevation GmbH
// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QString>

class QWidget;

namespace Kleo
{

/**
 * Checks that \p outDir is a valid path, a directory, and writable.
 * Creates it if necessary and shows error messages as needed.
 * Returns true if the folder is ready to be used.
 */
bool ensureOutputDirectoryExists(const QString &outDir, QWidget *parent);
}
