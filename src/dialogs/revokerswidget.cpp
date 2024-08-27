// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "revokerswidget.h"

#include "commands/command.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyList>
#include <Libkleo/TreeWidget>

#include <gpgme++/key.h>

#include <gpgme.h>

#include <KLocalizedString>
#include <KStandardAction>

#include <QClipboard>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QMenu>
#include <QVBoxLayout>

using namespace Kleo;

class RevokersWidget::Private
{
public:
    RevokersWidget *const q;

    enum Column {
        Fingerprint,
        Name,
        Email,
    };

    Private(RevokersWidget *qq)
        : q(qq)
        , ui{qq}
    {
        connect(ui.revokersTree, &QTreeWidget::doubleClicked, q, [this]() {
            const auto index = ui.revokersTree->currentIndex();
            if (!index.isValid()) {
                return;
            }
#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
            const auto fingerprint = QString::fromLatin1(key.revocationKey(ui.revokersTree->currentIndex().row()).fingerprint());
            auto cmd = Command::commandForQuery(fingerprint);
            cmd->setParentWidget(q->window());
            cmd->start();
#endif
        });
    }

public:
    GpgME::Key key;

public:
    struct UI {
        QVBoxLayout *mainLayout;
        TreeWidget *revokersTree;

        UI(QWidget *widget)
        {
            mainLayout = new QVBoxLayout{widget};
            mainLayout->setContentsMargins({});

            revokersTree = new TreeWidget{widget};
            revokersTree->setProperty("_breeze_force_frame", true);
            revokersTree->setHeaderLabels({
                i18nc("@title:column", "Fingerprint"),
                i18nc("@title:column", "Name"),
                i18nc("@title:column", "Email"),
            });
            revokersTree->setAccessibleName(i18nc("@label", "Revokers"));
            revokersTree->setContextMenuPolicy(Qt::CustomContextMenu);
            revokersTree->setRootIsDecorated(false);
            mainLayout->addWidget(revokersTree);
            connect(revokersTree, &QTreeWidget::customContextMenuRequested, widget, [widget, this](const auto &pos) {
                auto menu = new QMenu;
                menu->setAttribute(Qt::WA_DeleteOnClose, true);
                menu->addAction(KStandardAction::copy(
                    widget,
                    [this]() {
                        QGuiApplication::clipboard()->setText(revokersTree->currentIndex().data(Kleo::ClipboardRole).toString());
                    },
                    widget));
                menu->popup(widget->mapToGlobal(pos));
            });
        }
    } ui;
};

RevokersWidget::RevokersWidget(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{
}

RevokersWidget::~RevokersWidget() = default;

void RevokersWidget::setKey(const GpgME::Key &key)
{
    if (key.protocol() != GpgME::OpenPGP) {
        return;
    }
    d->key = key;

    d->ui.revokersTree->clear();

#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
    for (size_t i = 0; i < key.numRevocationKeys(); i++) {
        auto item = new QTreeWidgetItem;

        auto revoker = key.revocationKey(i);
        auto revokerKey = Kleo::KeyCache::instance()->findByFingerprint(revoker.fingerprint());
        item->setData(Private::Fingerprint, Qt::DisplayRole, Formatting::prettyID(revoker.fingerprint()));
        item->setData(Private::Fingerprint, Qt::AccessibleTextRole, Formatting::accessibleHexID(revoker.fingerprint()));
        item->setData(Private::Fingerprint, Kleo::ClipboardRole, QString::fromLatin1(revoker.fingerprint()));
        if (!revokerKey.isNull()) {
            item->setData(Private::Name, Qt::DisplayRole, Formatting::prettyName(revokerKey));
            item->setData(Private::Name, Kleo::ClipboardRole, Formatting::prettyName(revokerKey));
            item->setData(Private::Email, Qt::DisplayRole, Formatting::prettyEMail(revokerKey));
            item->setData(Private::Email, Kleo::ClipboardRole, Formatting::prettyEMail(revokerKey));
        } else {
            item->setData(Private::Name, Qt::DisplayRole, {});
            item->setData(Private::Email, Qt::DisplayRole, {});
            item->setData(Private::Name, Qt::AccessibleTextRole, i18nc("text for screen readers for an unknown name", "unknown name"));
            item->setData(Private::Email, Qt::AccessibleTextRole, i18nc("text for screen readers for an unknown email", "unknown email"));
            item->setData(Private::Name, Kleo::ClipboardRole, {});
            item->setData(Private::Email, Kleo::ClipboardRole, {});
        }

        d->ui.revokersTree->addTopLevelItem(item);
    }
#endif
    QMetaObject::invokeMethod(
        this,
        [this]() {
            if (!d->ui.revokersTree->restoreColumnLayout(QStringLiteral("RevokersWidget"))) {
                d->ui.revokersTree->resizeToContentsLimited();
            }
        },
        Qt::QueuedConnection);
}

GpgME::Key RevokersWidget::key() const
{
    return d->key;
}

#include "moc_revokerswidget.cpp"
