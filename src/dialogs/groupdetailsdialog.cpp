/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "groupdetailsdialog.h"

#include "commands/detailscommand.h"
#include "view/keytreeview.h"

#include <Libkleo/KeyGroup>
#include <Libkleo/KeyListModel>

#include <KConfigGroup>
#include <KGuiItem>
#include <KLocalizedString>
#include <KSharedConfig>
#include <KStandardGuiItem>

#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QTreeView>
#include <QVBoxLayout>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Dialogs;

Q_DECLARE_METATYPE(GpgME::Key)

class GroupDetailsDialog::Private
{
    friend class ::Kleo::Dialogs::GroupDetailsDialog;
    GroupDetailsDialog *const q;

    struct {
        QLabel *groupNameLabel = nullptr;
        QLabel *groupCommentLabel = nullptr;
        KeyTreeView *treeView = nullptr;
        QDialogButtonBox *buttonBox = nullptr;
    } ui;
    KeyGroup group;

public:
    Private(GroupDetailsDialog *qq)
        : q(qq)
    {
        auto mainLayout = new QVBoxLayout(q);

        ui.groupNameLabel = new QLabel();
        ui.groupNameLabel->setWordWrap(true);
        mainLayout->addWidget(ui.groupNameLabel);

        ui.groupCommentLabel = new QLabel();
        ui.groupCommentLabel->setWordWrap(true);
        ui.groupCommentLabel->setVisible(false);
        mainLayout->addWidget(ui.groupCommentLabel);

        ui.treeView = new KeyTreeView(q);
        ui.treeView->view()->setRootIsDecorated(false);
        ui.treeView->view()->setSelectionMode(QAbstractItemView::SingleSelection);
        ui.treeView->setFlatModel(AbstractKeyListModel::createFlatKeyListModel(ui.treeView));
        ui.treeView->setHierarchicalView(false);
        connect(ui.treeView->view(), &QAbstractItemView::doubleClicked, q, [this](const QModelIndex &index) {
            showKeyDetails(index);
        });
        mainLayout->addWidget(ui.treeView);

        ui.buttonBox = new QDialogButtonBox(QDialogButtonBox::Close);
        KGuiItem::assign(ui.buttonBox->button(QDialogButtonBox::Close), KStandardGuiItem::close());
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &QDialog::close);
        mainLayout->addWidget(ui.buttonBox);

        // calculate default size with enough space for the key list
        const auto fm = ui.treeView->fontMetrics();
        const QSize sizeHint = q->sizeHint();
        const QSize defaultSize = QSize(qMax(sizeHint.width(), 150 * fm.horizontalAdvance(QLatin1Char('x'))),
                                        sizeHint.height() - ui.treeView->sizeHint().height() + 20 * fm.lineSpacing());
        restoreLayout(defaultSize);
    }

    ~Private()
    {
        saveLayout();
    }

private:
    void saveLayout()
    {
        KConfigGroup configGroup(KSharedConfig::openStateConfig(), QStringLiteral("GroupDetailsDialog"));
        configGroup.writeEntry("Size", q->size());
        configGroup.sync();
    }

    void restoreLayout(const QSize &defaultSize)
    {
        const KConfigGroup configGroup(KSharedConfig::openStateConfig(), QStringLiteral("GroupDetailsDialog"));
        ui.treeView->restoreLayout(configGroup);
        const QSize size = configGroup.readEntry("Size", defaultSize);
        if (size.isValid()) {
            q->resize(size);
        }
    }

    void showKeyDetails(const QModelIndex &index)
    {
        const auto key = ui.treeView->view()->model()->data(index, KeyList::KeyRole).value<GpgME::Key>();
        if (!key.isNull()) {
            auto cmd = new DetailsCommand(key);
            cmd->setParentWidget(q);
            cmd->start();
        }
    }
};

GroupDetailsDialog::GroupDetailsDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
    setWindowTitle(i18nc("@title:window", "Group Details"));
}

GroupDetailsDialog::~GroupDetailsDialog()
{
}

namespace
{
QString groupComment(const KeyGroup &group)
{
    switch (group.source()) {
    case KeyGroup::GnuPGConfig:
        return i18n("Note: This group is defined in the configuration files of gpg.");
    default:
        return QString();
    }
}
}

void GroupDetailsDialog::setGroup(const KeyGroup &group)
{
    d->group = group;
    d->ui.groupNameLabel->setText(group.name());
    d->ui.groupCommentLabel->setText(groupComment(group));
    d->ui.groupCommentLabel->setVisible(!d->ui.groupCommentLabel->text().isEmpty());
    const KeyGroup::Keys &keys = group.keys();
    d->ui.treeView->setKeys(std::vector<GpgME::Key>(keys.cbegin(), keys.cend()));
}

#include "moc_groupdetailsdialog.cpp"
