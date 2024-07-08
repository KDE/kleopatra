/*  utils/overwritedialog.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QDialog>

#include <memory>

namespace Kleo
{

/**
 * @class Kleo::OverwriteDialog overwritedialog.h <overwritedialog.h>
 *
 * This dialog can be shown when you realize that a file you want to write
 * already exists and you want to offer the user the choice to either Rename,
 * Overwrite, Append, or Skip.
 */
class OverwriteDialog : public QDialog
{
    Q_OBJECT
public:
    /**
     * @see Options
     */
    enum Option {
        AllowRename = 1, ///< Allow the user to enter a different file name.
        AllowSkip = 2, ///< Offer a "Skip" button, to skip other files too. Requires MultipleItems.
        MultipleItems =
            4, ///< Set if the current operation concerns multiple files, so it makes sense to offer buttons that apply the user's choice to all files/folders.
        AllowAppend = 8, ///< Allow the user to choose Append.
    };
    /**
     * Stores a combination of #Option values.
     */
    Q_DECLARE_FLAGS(Options, Option)

    enum Result {
        Cancel = 0, // = QDialog::Rejected
        Overwrite = 1,
        OverwriteAll = 2,
        Rename = 3,
        AutoRename = 4,
        Skip = 5,
        AutoSkip = 6,
        Append = 7,
    };

    /**
     * Construct an "overwrite" dialog to let the user know that the file @p fileName is about to be overwritten.
     *
     * @param parent parent widget
     * @param title the title for the dialog
     * @param fileName the path of the file that already exists
     * @param options parameters for the dialog (which buttons to show...),
     */
    OverwriteDialog(QWidget *parent, const QString &title, const QString &fileName, Options options);

    ~OverwriteDialog() override;

    /**
     * Returns the new file name to use if the user selected the Rename option.
     * Otherwise, returns an empty string.
     *
     * @return the new file name or an empty string
     */
    QString newFileName() const;

private:
    class Private;
    std::unique_ptr<Private> const d;
};
}

Q_DECLARE_OPERATORS_FOR_FLAGS(Kleo::OverwriteDialog::Options)
