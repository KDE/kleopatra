/* -*- mode: c++; c-basic-offset:4 -*-
    commands/command.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include <qwindowdefs.h> // for WId

#include <utils/types.h> // for ExecutionContext

#include <memory>
#include <vector>

class QModelIndex;
template<typename T>
class QList;
class QAbstractItemView;

namespace GpgME
{
class Key;
}

namespace Kleo
{

class KeyListController;
class AbstractKeyListSortFilterProxyModel;

class Command : public QObject, public ExecutionContext
{
    Q_OBJECT
public:
    explicit Command(KeyListController *parent);
    explicit Command(QAbstractItemView *view, KeyListController *parent);
    explicit Command(const GpgME::Key &key);
    explicit Command(const std::vector<GpgME::Key> &keys);
    ~Command() override;

    enum Restriction {
        // clang-format off
        NoRestriction      = 0x0000,
        NeedSelection      = 0x0001,
        OnlyOneKey         = 0x0002,
        NeedSecretKey      = 0x0004, //< command performs secret key operations
        NeedSecretPrimaryKeyData  = 0x0008, //< command needs access to the secret key data of the primary key
        NeedSecretSubkeyData      = 0x0010, //< command needs access to the secret key data of one or more subkeys

        // esoteric:
        MayOnlyBeSecretKeyIfOwnerTrustIsNotYetUltimate = 0x0040, // for set-owner-trust

        AnyCardHasNullPin   = 0x0080,
        SuitableForCard     = 0x0100,

        MustBeRoot          = 0x0200,
        MustBeTrustedRoot   = 0x0400 | MustBeRoot,
        MustBeUntrustedRoot = 0x0800 | MustBeRoot,

        MustBeValid         = 0x1000, //< key is neither revoked nor expired nor otherwise "bad"
        MustBeOpenPGP       = 0x2000,
        MustBeCMS           = 0x4000,

        _AllRestrictions_Helper,
        AllRestrictions = 2 * (_AllRestrictions_Helper - 1) - 1,
        // clang-format on
    };

    Q_DECLARE_FLAGS(Restrictions, Restriction)

    static Restrictions restrictions()
    {
        return NoRestriction;
    }

    /** Classify the files and return the most appropriate commands.
     *
     * @param files: A list of files.
     *
     * @returns null QString on success. Error message otherwise.
     */
    static QList<Command *> commandsForFiles(const QStringList &files, KeyListController *controller);

    /** Get a command for a query.
     *
     * @param query: A keyid / fingerprint or any string to use in the search.
     */
    static Command *commandForQuery(const QString &query);

    void setParentWidget(QWidget *widget);

    // Prefer Command::setParentWidget over Command::setParentWId; QWidget::winId can cause unexpected problems
    // when called on non-toplevel widgets
    void setParentWId(WId wid);
    void setView(QAbstractItemView *view);
    void setKey(const GpgME::Key &key);
    void setKeys(const std::vector<GpgME::Key> &keys);

    void setAutoDelete(bool on);
    bool autoDelete() const;

    void setWarnWhenRunningAtShutdown(bool warn);
    bool warnWhenRunningAtShutdown() const;

public Q_SLOTS:
    void start();
    void cancel();

Q_SIGNALS:
    void info(const QString &message, int timeout = 0);
    void progress(int current, int total);
    void finished();
    void canceled();

private:
    virtual void doStart() = 0;
    virtual void doCancel() = 0;

private:
    void applyWindowID(QWidget *wid) const override;

protected:
    void addTemporaryView(const QString &title, AbstractKeyListSortFilterProxyModel *proxy = nullptr, const QString &tabToolTip = QString());

protected:
    class Private;
    const std::unique_ptr<Private> d;

protected:
    explicit Command(Private *pp);
    explicit Command(QAbstractItemView *view, Private *pp);
    explicit Command(const std::vector<GpgME::Key> &keys, Private *pp);
    explicit Command(const GpgME::Key &key, Private *pp);
};

Q_DECLARE_OPERATORS_FOR_FLAGS(Command::Restrictions)

}
