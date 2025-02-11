/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

class QString;

namespace ApplicationState
{

/**
 * Reads the last used export directory from the application state config file.
 */
QString lastUsedExportDirectory();

/**
 * Writes the last used export directory to the application state config file.
 * If \p path references a file, then the file name is stripped. The path is
 * written as absolute path.
 */
void setLastUsedExportDirectory(const QString &path);

}
