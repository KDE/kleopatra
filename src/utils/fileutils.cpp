// SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
// SPDX-FileContributor: Intevation GmbH
// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "fileutils.h"

#include "path-helper.h"

#include <kleopatra_debug.h>

#include <KLocalizedString>
#include <KMessageBox>

#include <QDir>
#include <QFileInfo>

bool Kleo::ensureOutputDirectoryExists(const QString &outputDirectory, QWidget *parent)
{
    if (outputDirectory.isEmpty()) {
        KMessageBox::information(parent, i18n("Please select an output folder."), i18nc("@title:window", "No Output Folder"));
        return false;
    }
    const QFileInfo fi(outputDirectory);

    if (!fi.exists()) {
        qCDebug(KLEOPATRA_LOG) << "Output dir does not exist. Trying to create.";
        const QDir dir(outputDirectory);
        if (!dir.mkdir(outputDirectory)) {
            KMessageBox::information(
                parent,
                xi18nc("@info",
                       "<para>Failed to create output folder <filename>%1</filename>.</para><para>Please select a different output folder.</para>",
                       outputDirectory),
                i18nc("@title:window", "Unusable Output Folder"));
            return false;
        } else {
            return true;
        }
    } else if (!fi.isDir()) {
        KMessageBox::information(parent, i18n("Please select a different output folder."), i18nc("@title:window", "Invalid Output Folder"));
        return false;
    } else if (!Kleo::isWritable(fi)) {
        KMessageBox::information(
            parent,
            xi18nc("@info",
                   "<para>Cannot write in the output folder <filename>%1</filename>.</para><para>Please select a different output folder.</para>",
                   outputDirectory),
            i18nc("@title:window", "Unusable Output Folder"));
        return false;
    }
    return true;
}
