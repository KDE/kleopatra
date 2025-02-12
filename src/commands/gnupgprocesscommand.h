/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

#include <QStringList>
class QString;
class QProcess;

namespace Kleo
{
namespace Commands
{

class GnuPGProcessCommand : public Command
{
    Q_OBJECT
protected:
    GnuPGProcessCommand(QAbstractItemView *view, KeyListController *parent);
    explicit GnuPGProcessCommand(KeyListController *parent);
    explicit GnuPGProcessCommand(const GpgME::Key &key);
    explicit GnuPGProcessCommand(const std::vector<GpgME::Key> &keys);
    ~GnuPGProcessCommand() override;

public:
    QDialog *dialog() const;
    void setShowsOutputWindow(bool show);
    bool success() const;
    void setInteractive(bool interactive);
    bool interactive() const;

private:
    virtual bool preStartHook(QWidget *parentWidget) const;

    virtual QStringList arguments() const = 0;

    virtual QString errorCaption() const = 0;
    virtual QString successCaption() const;

    virtual QString crashExitMessage(const QStringList &args) const = 0;
    virtual QString errorExitMessage(const QStringList &args) const = 0;
    virtual QString successMessage(const QStringList &args) const;

    virtual void postSuccessHook(QWidget *parentWidget);

protected:
    QString errorString() const;
    void setIgnoresSuccessOrFailure(bool ignore);
    bool ignoresSuccessOrFailure() const;
    bool showsOutputWindow() const;

    QProcess *process();

    void doStart() override;
    void doCancel() override;

    QMetaObject::Connection m_procReadyReadStdErrConnection;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

}
}
