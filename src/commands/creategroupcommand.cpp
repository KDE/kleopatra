/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "creategroupcommand.h"

#include "command_p.h"
#include "dialogs/editgroupdialog.h"

#include <Libkleo/Compat>
#include <Libkleo/KeyCache>

#include <gpgme++/key.h>

#include <KRandom>

#include <memory>

using namespace Kleo;
using namespace GpgME;
using namespace Kleo::Dialogs;

class CreateGroupCommand::Private : public Command::Private
{
    friend class ::CreateGroupCommand;
    CreateGroupCommand *q_func() const
    {
        return static_cast<CreateGroupCommand *>(q);
    }

public:
    using Command::Private::Private;
    ~Private() override;
    void showEditGroupDialog(KeyGroup group, const QString &windowTitle, EditGroupDialog::FocusWidget focusWidget);
};

CreateGroupCommand::Private *CreateGroupCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const CreateGroupCommand::Private *CreateGroupCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

CreateGroupCommand::Private::~Private() = default;

CreateGroupCommand::CreateGroupCommand(QAbstractItemView *v, KeyListController *p)
    : Command(v, new Private(this, p))
{
}

CreateGroupCommand::~CreateGroupCommand() = default;

void CreateGroupCommand::doCancel()
{
}

void CreateGroupCommand::Private::showEditGroupDialog(KeyGroup group, const QString &windowTitle, EditGroupDialog::FocusWidget focusWidget)
{
    auto dialog = new EditGroupDialog(parentWidgetOrView());
    dialog->setWindowTitle(windowTitle);
    dialog->setKeyGroup(group);
    dialog->setInitialFocus(focusWidget);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    dialog->show();

    connect(dialog, &QDialog::finished, q, [dialog, this](const auto result) {
        if (result == QDialog::Rejected) {
            canceled();
            return;
        }

        const auto newGroup = dialog->keyGroup();

        if (!newGroup.isNull()) {
            auto groups = KeyCache::instance()->configurableGroups();
            groups.push_back(newGroup);
            KeyCache::mutableInstance()->saveConfigurableGroups(groups);
        }
        finished();
    });
}

void CreateGroupCommand::doStart()
{
    auto keys = d->keys();
    auto removed = std::erase_if(keys, [](const auto &key) {
        return !Kleo::keyHasEncrypt(key);
    });

    if (removed == d->keys().size()) {
        KMessageBox::information(d->parentWidgetOrView(), i18n("None of the selected certificates can be used for encryption. No group will be created."));
        return;
    }
    if (removed > 0) {
        KMessageBox::information(d->parentWidgetOrView(),
                                 i18n("Some of the selected certificates cannot be used for encryption. These will not be added to the group."));
    }

    const KeyGroup::Id newId = KRandom::randomString(8);
    KeyGroup group = KeyGroup(newId, i18nc("default name for new group of keys", "New Group"), {}, KeyGroup::ApplicationConfig);
    group.setIsImmutable(false);

    group.setKeys(keys);

    d->showEditGroupDialog(group, i18nc("@title:window a group of keys", "New Group"), EditGroupDialog::GroupName);
}
