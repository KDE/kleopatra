/* -*- mode: c++; c-basic-offset:4 -*-
    commands/command_p.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"
#include "view/keylistcontroller.h"

#include <Libkleo/KeyListModel>

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
        Q_EMIT q->finished();
        doFinish();
        if (autoDelete) {
            q->deleteLater();
        }
    }

    void canceled()
    {
        Q_EMIT q->canceled();
        finished();
    }

    void error(const QString &text, const QString &caption = QString(), KMessageBox::Options options = KMessageBox::Notify) const
    {
        if (parentWId_) {
            KMessageBox::errorWId(parentWId_, text, caption, options);
        } else {
            KMessageBox::error(parentWidgetOrView(), text, caption, options);
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
    void information(const QString &text, const QString &caption = QString(), const QString &dontShowAgainName = QString(), KMessageBox::Options options = KMessageBox::Notify) const
    {
        if (parentWId_) {
            KMessageBox::informationWId(parentWId_, text, caption, dontShowAgainName, options);
        } else {
            KMessageBox::information(parentWidgetOrView(), text, caption, dontShowAgainName, options);
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

