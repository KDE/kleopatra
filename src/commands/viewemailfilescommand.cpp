// This file is part of Kleopatra, the KDE keymanager
// SPDX-FileCopyrightText: 2023 g10 Code GmbH
// SPDX-FileContributor: Carl Schwan <carl.schwan@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "viewemailfilescommand.h"

#include "command_p.h"

#include <MimeTreeParserWidgets/MessageViewerDialog>

using namespace Kleo::Commands;
using namespace MimeTreeParser::Widgets;

class ViewEmailFilesCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::ViewEmailFilesCommand;
    ViewEmailFilesCommand *q_func() const
    {
        return static_cast<ViewEmailFilesCommand *>(q);
    }

public:
    Private(ViewEmailFilesCommand *qq, KeyListController *c);
    ~Private() override;

    QList<QPointer<MessageViewerDialog>> dialogs;
    QStringList files;

    void ensureDialogCreated();
};

ViewEmailFilesCommand::Private::Private(ViewEmailFilesCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
{
}

ViewEmailFilesCommand::Private::~Private() = default;

void ViewEmailFilesCommand::Private::ensureDialogCreated()
{
    for (const auto &file : std::as_const(files)) {
        const auto dlg = new MessageViewerDialog(file);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        connect(dlg, &MessageViewerDialog::finished, q_func(), [this, dlg] {
            dialogs.removeAll(dlg);
            if (dialogs.isEmpty()) {
                finished();
            }
        });
        dialogs << dlg;
        dlg->show();
        dlg->raise();
        dlg->activateWindow();
    }
}

ViewEmailFilesCommand::Private *ViewEmailFilesCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ViewEmailFilesCommand::Private *ViewEmailFilesCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ViewEmailFilesCommand::ViewEmailFilesCommand(const QStringList &files, KeyListController *c)
    : Command(new Private(this, c))
{
    Q_ASSERT(!files.isEmpty());

    setWarnWhenRunningAtShutdown(false);

    d->files = files;
}

ViewEmailFilesCommand::~ViewEmailFilesCommand() = default;

void ViewEmailFilesCommand::doStart()
{
    d->ensureDialogCreated();
}

void ViewEmailFilesCommand::doCancel()
{
    for (const auto &dialog : std::as_const(d->dialogs)) {
        dialog->close();
    }
}

#include "moc_viewemailfilescommand.cpp"
