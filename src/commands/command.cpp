/* -*- mode: c++; c-basic-offset:4 -*-
    commands/command.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "command.h"
#include "command_p.h"

#include "checksumverifyfilescommand.h"
#include "decryptverifyfilescommand.h"
#include "detailscommand.h"
#include "importcertificatefromfilecommand.h"
#include "lookupcertificatescommand.h"
#include "signencryptfilescommand.h"
#include "viewemailfilescommand.h"

#include <Libkleo/Classify>
#include <Libkleo/KeyCache>

#include <view/tabwidget.h>

#include "kleopatra_debug.h"
#include <KWindowSystem>

#include <QAbstractItemView>
#include <QFileInfo>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

Command::Private::Private(Command *qq)
    : q(qq)
    , autoDelete(true)
    , warnWhenRunningAtShutdown(true)
{
}

Command::Private::Private(Command *qq, KeyListController *controller)
    : q(qq)
    , autoDelete(true)
    , warnWhenRunningAtShutdown(true)
    , controller_(controller)
{
}

Command::Private::Private(Command *qq, QWidget *parent)
    : q(qq)
    , autoDelete(true)
    , warnWhenRunningAtShutdown(true)
    , parentWidget_(parent)
{
}

Command::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
}

Command::Command(KeyListController *p)
    : QObject(p)
    , d(new Private(this, p))
{
    if (p) {
        p->registerCommand(this);
    }
}

Command::Command(QAbstractItemView *v, KeyListController *p)
    : QObject(p)
    , d(new Private(this, p))
{
    if (p) {
        p->registerCommand(this);
    }
    if (v) {
        setView(v);
    }
}

Command::Command(Private *pp)
    : QObject(pp->controller_)
    , d(pp)
{
    if (pp->controller_) {
        pp->controller_->registerCommand(this);
    }
}

Command::Command(QAbstractItemView *v, Private *pp)
    : QObject(pp->controller_)
    , d(pp)
{
    if (pp->controller_) {
        pp->controller_->registerCommand(this);
    }
    if (v) {
        setView(v);
    }
}

Command::Command(const GpgME::Key &key)
    : QObject(nullptr)
    , d(new Private(this))
{
    d->keys_ = std::vector<Key>(1, key);
}

Command::Command(const std::vector<GpgME::Key> &keys)
    : QObject(nullptr)
    , d(new Private(this))
{
    d->keys_ = keys;
}

Command::Command(const Key &key, Private *pp)
    : QObject(nullptr)
    , d(pp)
{
    d->keys_ = std::vector<Key>(1, key);
}

Command::Command(const std::vector<GpgME::Key> &keys, Private *pp)
    : QObject(nullptr)
    , d(pp)
{
    d->keys_ = keys;
}

Command::~Command()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
}

void Command::setAutoDelete(bool on)
{
    d->autoDelete = on;
}

bool Command::autoDelete() const
{
    return d->autoDelete;
}

void Command::setWarnWhenRunningAtShutdown(bool on)
{
    d->warnWhenRunningAtShutdown = on;
}

bool Command::warnWhenRunningAtShutdown() const
{
    return d->warnWhenRunningAtShutdown;
}

void Command::setParentWidget(QWidget *widget)
{
    d->parentWidget_ = widget;
}

void Command::setParentWId(WId wid)
{
    d->parentWId_ = wid;
}

void Command::setView(QAbstractItemView *view)
{
    if (view == d->view_) {
        return;
    }
    d->view_ = view;
    if (!view || !d->keys_.empty()) {
        return;
    }
    const auto *const keyListModel = dynamic_cast<KeyListModelInterface *>(view->model());
    if (!keyListModel) {
        qCWarning(KLEOPATRA_LOG) << "view" << view << "has not key list model";
        return;
    }
    const QItemSelectionModel *const sm = view->selectionModel();
    if (!sm) {
        qCWarning(KLEOPATRA_LOG) << "view" << view << "has no selection model";
        return;
    }
    const QList<QModelIndex> selected = sm->selectedRows();
    std::transform(selected.begin(), selected.end(), std::back_inserter(d->keys_), [keyListModel](const auto &idx) {
        return keyListModel->key(idx);
    });
}

void Command::setKey(const Key &key)
{
    d->keys_.clear();
    if (!key.isNull()) {
        d->keys_.push_back(key);
    }
}

void Command::setKeys(const std::vector<Key> &keys)
{
    d->keys_ = keys;
}

void Command::start()
{
    // defer the actual start and return immediately to avoid problems if the
    // caller is deleted before start returns (e.g. an action of a context menu)
    QMetaObject::invokeMethod(
        this,
        [this]() {
            doStart();
        },
        Qt::QueuedConnection);
}

void Command::cancel()
{
    qCDebug(KLEOPATRA_LOG) << metaObject()->className();
    doCancel();
    Q_EMIT canceled();
}

void Command::addTemporaryView(const QString &title, AbstractKeyListSortFilterProxyModel *proxy, const QString &tabToolTip)
{
    if (TabWidget *const tw = d->controller_ ? d->controller_->tabWidget() : nullptr)
        if (QAbstractItemView *const v = tw->addTemporaryView(title, proxy, tabToolTip)) {
            setView(v);
        }
}

void Command::applyWindowID(QWidget *w) const
{
    if (w) {
        if (d->parentWId()) {
            if (QWidget *pw = QWidget::find(d->parentWId())) {
                // remember the current focus widget; re-parenting resets it
                QWidget *focusWidget = w->focusWidget();
                w->setParent(pw, w->windowFlags());
                if (focusWidget) {
                    focusWidget->setFocus();
                }
            } else {
                w->setAttribute(Qt::WA_NativeWindow, true);
                KWindowSystem::setMainWindow(w->windowHandle(), d->parentWId());
            }
        } else {
            // remember the current focus widget; re-parenting resets it
            QWidget *focusWidget = w->focusWidget();
            w->setParent(d->parentWidgetOrView(), w->windowFlags());
            if (focusWidget) {
                focusWidget->setFocus();
            }
        }
    }
}

// static
QList<Command *> Command::commandsForFiles(const QStringList &files, KeyListController *controller)
{
    QStringList importFiles, decryptFiles, encryptFiles, checksumFiles, emailFiles;
    QList<Command *> cmds;
    for (const QString &fileName : files) {
        const unsigned int classification = classify(fileName);

        if (classification & Class::MimeFile) {
            emailFiles << fileName;
        } else if (classification & Class::AnyCertStoreType) {
            importFiles << fileName;
        } else if (classification & Class::AnyMessageType) {
            // For any message we decrypt / verify. This includes
            // the class CipherText
            decryptFiles << fileName;
        } else if (isChecksumFile(fileName)) {
            checksumFiles << fileName;
        } else {
            QFileInfo fi(fileName);
            if (fi.isReadable()) {
                encryptFiles << fileName;
            }
        }
    }
    if (!importFiles.isEmpty()) {
        cmds << new ImportCertificateFromFileCommand(importFiles, controller);
    }
    if (!decryptFiles.isEmpty()) {
        cmds << new DecryptVerifyFilesCommand(decryptFiles, controller);
    }
    if (!encryptFiles.isEmpty()) {
        cmds << new SignEncryptFilesCommand(encryptFiles, controller);
    }
    if (!checksumFiles.isEmpty()) {
        cmds << new ChecksumVerifyFilesCommand(checksumFiles, controller);
    }
    if (!emailFiles.isEmpty()) {
        cmds << new ViewEmailFilesCommand(emailFiles, controller);
    }
    return cmds;
}

// static
Command *Command::commandForQuery(const QString &query)
{
    const auto cache = Kleo::KeyCache::instance();
    GpgME::Key key = cache->findByKeyIDOrFingerprint(query.toLocal8Bit().data());

    if (key.isNull() && Kleo::isFingerprint(query)) {
        // Try to find the key by subkey fingerprint
        const auto subkey = cache->findSubkeyByFingerprint(query.toStdString());
        if (!subkey.isNull()) {
            key = subkey.parent();
        }
    }
    if (key.isNull()) {
        return new LookupCertificatesCommand(query, nullptr);
    } else {
        return new DetailsCommand(key);
    }
}

#include "moc_command.cpp"
