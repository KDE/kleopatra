// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

namespace Migration
{
#ifdef Q_OS_WIN
/// Copies the application config files appnamerc and appnamestaterc from the old location to GNUPGHOME/kleopatra.
void migrateApplicationConfigFiles(const QString &applicationName);
#endif

void migrate();
}
