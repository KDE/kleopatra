/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "groupsconfigdialog.h"

#include "groupsconfigwidget.h"

#include <kleopatra_debug.h>
#include <utils/gui-helper.h>

#include <Libkleo/DocAction>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyGroup>

#include <KAdjustingScrollArea>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QDialogButtonBox>
#include <QPushButton>
#include <QVBoxLayout>

using namespace Kleo;

class GroupsConfigDialog::Private
{
    friend class ::GroupsConfigDialog;
    GroupsConfigDialog *const q;

public:
    Private(GroupsConfigDialog *qq)
        : q(qq)
    {
    }

private:
    void saveLayout();
    void restoreLayout(const QSize &defaultSize = {});

    void loadGroups();
    void saveGroups();

    void onKeysMayHaveChanged();

private:
    GroupsConfigWidget *configWidget = nullptr;

    bool savingChanges = false;
};

void GroupsConfigDialog::Private::saveLayout()
{
    KConfigGroup configGroup(KSharedConfig::openStateConfig(), QLatin1StringView("GroupsConfigDialog"));
    configGroup.writeEntry("Size", q->size());
    configGroup.sync();
}

void GroupsConfigDialog::Private::restoreLayout(const QSize &defaultSize)
{
    const KConfigGroup configGroup(KSharedConfig::openStateConfig(), QLatin1StringView("GroupsConfigDialog"));
    const QSize size = configGroup.readEntry("Size", defaultSize);
    if (size.isValid()) {
        q->resize(size);
    }
}

void GroupsConfigDialog::Private::loadGroups()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
    configWidget->setGroups(KeyCache::instance()->configurableGroups());
}

void GroupsConfigDialog::Private::saveGroups()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
    savingChanges = true;
    KeyCache::mutableInstance()->saveConfigurableGroups(configWidget->groups());
    savingChanges = false;

    // reload after saving to ensure that the groups reflect the saved groups (e.g. in case of immutable entries)
    loadGroups();
}

void GroupsConfigDialog::Private::onKeysMayHaveChanged()
{
    if (savingChanges) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "ignoring changes caused by ourselves";
        return;
    }
    qCDebug(KLEOPATRA_LOG) << "Reloading groups";
    loadGroups();
}

GroupsConfigDialog::GroupsConfigDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
    setWindowTitle(i18nc("@title:window", "Configure Groups"));

    auto mainLayout = new QVBoxLayout{this};

    auto scrollArea = new KAdjustingScrollArea{this};
    scrollArea->setFocusPolicy(Qt::NoFocus);
    scrollArea->setFrameStyle(QFrame::NoFrame);
    scrollArea->setBackgroundRole(backgroundRole());
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
    auto widget = new QWidget;
    scrollArea->setWidget(widget);
    auto scrollAreaLayout = new QVBoxLayout(widget);
    scrollAreaLayout->setContentsMargins({});

    d->configWidget = new GroupsConfigWidget{this};
    d->configWidget->setContentsMargins({});
    scrollAreaLayout->addWidget(d->configWidget);

    mainLayout->addWidget(scrollArea);

    auto buttonBox = new QDialogButtonBox{QDialogButtonBox::Close, this};

    mainLayout->addWidget(buttonBox);

    auto helpAction = std::make_unique<Kleo::DocAction>(
        QIcon::fromTheme(QStringLiteral("help")),
        i18n("Help"),
        i18nc("Only available in German and English. Leave to English for other languages.", "handout_group-feature_gnupg_en.pdf"),
        QStringLiteral("../share/doc/gnupg-vsd"),
        QUrl(),
        this);
    if (helpAction->isEnabled()) {
        auto helpButton = buttonBox->addButton(QDialogButtonBox::Help);
        disconnect(helpButton, &QAbstractButton::clicked, nullptr, nullptr);
        connect(helpButton, &QAbstractButton::clicked, helpAction.get(), &QAction::trigger);
        helpAction.release();
    }

    // prevent accidental closing of dialog when pressing Enter while the search field has focus
    Kleo::unsetAutoDefaultButtons(this);

    // Close button (defined with RejectRole) should close the dialog
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::accept);

    connect(d->configWidget, &GroupsConfigWidget::changed, this, [this]() {
        d->saveGroups();
    });

    connect(KeyCache::instance().get(), &KeyCache::keysMayHaveChanged, this, [this]() {
        d->onKeysMayHaveChanged();
    });

    d->restoreLayout();
    d->loadGroups();
}

GroupsConfigDialog::~GroupsConfigDialog()
{
    d->saveLayout();
}

#include "moc_groupsconfigdialog.cpp"
