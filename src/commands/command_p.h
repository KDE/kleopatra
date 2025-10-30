/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"
#include "view/keylistcontroller.h"

#include <Libkleo/AuditLogEntry>
#include <Libkleo/KeyListModel>
#include <Libkleo/MessageBox>

#include <KLocalizedString>
#include <KMessageBox>

#include <QAbstractItemView>
#include <QPointer>

#include <gpgme++/key.h>

#include <algorithm>
#include <iterator>

class Kleo::Command::Private
{
    friend class ::Kleo::Command;

protected:
    Command *const q;

public:
    explicit Private(Command *qq);
    explicit Private(Command *qq, KeyListController *controller);
    explicit Private(Command *qq, QWidget *parent);
    virtual ~Private();

    QAbstractItemView *view() const
    {
        return view_;
    }
    QWidget *parentWidgetOrView() const
    {
        if (parentWidget_) {
            return parentWidget_;
        } else {
            return view_;
        }
    }
    WId parentWId() const
    {
        return parentWId_;
    }
    GpgME::Key key() const
    {
        return keys_.empty() ? GpgME::Key{} : keys_.front();
    }
    std::vector<GpgME::Key> keys() const
    {
        return keys_;
    }

    void finished()
    {
        Q_EMIT q->finished(QPrivateSignal{});
        doFinish();
        if (autoDelete) {
            q->deleteLater();
        }
    }

    void canceled()
    {
        Q_EMIT q->canceled(QPrivateSignal{});
        finished();
    }

    void error(const QString &text, const QString &title = QString(), KMessageBox::Options options = KMessageBox::Notify) const
    {
        error(text, AuditLogEntry{}, title, options);
    }

    void error(const QString &text, const Kleo::AuditLogEntry &auditLog, const QString &title = {}, KMessageBox::Options options = KMessageBox::Notify) const
    {
        if (parentWId_) {
            Kleo::MessageBox::errorWId(parentWId_, text, auditLog, title, options);
        } else {
            Kleo::MessageBox::error(parentWidgetOrView(), text, auditLog, title, options);
        }
    }

    void success(const QString &text, const QString &caption = {}, KMessageBox::Options options = KMessageBox::Notify) const
    {
        static const QString noDontShowAgainName{};
        const QString title = caption.isEmpty() ? i18nc("@title:window", "Success") : caption;
        if (parentWId_) {
            KMessageBox::informationWId(parentWId_, text, title, noDontShowAgainName, options);
        } else {
            KMessageBox::information(parentWidgetOrView(), text, title, noDontShowAgainName, options);
        }
    }
    void information(const QString &text,
                     const QString &caption = QString(),
                     const QString &dontShowAgainName = QString(),
                     KMessageBox::Options options = KMessageBox::Notify) const
    {
        if (parentWId_) {
            KMessageBox::informationWId(parentWId_, text, caption, dontShowAgainName, options);
        } else {
            KMessageBox::information(parentWidgetOrView(), text, caption, dontShowAgainName, options);
        }
    }
    void informationList(const QString &text,
                         const QStringList &strlist,
                         const QString &title = {},
                         const QString &dontShowAgainName = {},
                         KMessageBox::Options options = KMessageBox::Notify) const
    {
        if (parentWId_) {
            KMessageBox::informationListWId(parentWId_, text, strlist, title, dontShowAgainName, options);
        } else {
            KMessageBox::informationList(parentWidgetOrView(), text, strlist, title, dontShowAgainName, options);
        }
    }

    void applyWindowID(QWidget *w) const
    {
        q->applyWindowID(w);
    }

private:
    virtual void doFinish()
    {
    }

private:
    bool autoDelete : 1;
    bool warnWhenRunningAtShutdown : 1;
    std::vector<GpgME::Key> keys_;
    QPointer<QAbstractItemView> view_;
    QPointer<QWidget> parentWidget_;
    WId parentWId_ = 0;
    QPointer<KeyListController> controller_;
};
