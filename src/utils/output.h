/* -*- mode: c++; c-basic-offset:4 -*-
    utils/output.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <assuan.h> // for assuan_fd_t

#include <QString>
#include <QStringList>

#include <memory>

class QIODevice;
class QDir;
class QWidget;

namespace Kleo
{

class OverwritePolicy
{
public:
    enum Policy {
        None, ///< indicates an error
        Ask,
        Append,
        Overwrite,
        Rename,
        Skip,
        Cancel,
    };

    enum Options {
        MultipleFiles = 0x01,
        AllowAppend = 0x02,
    };

    struct PolicyAndFileName {
        // define explicit constructor to implicitly delete default constructor
        PolicyAndFileName(Policy p, const QString &f)
            : policy{p}
            , fileName{f}
        {
        }
        Policy policy;
        QString fileName;
    };

    explicit OverwritePolicy(Policy initialPolicy);
    /// creates an interactive policy, i.e. with initial policy set to Ask
    OverwritePolicy(QWidget *parent, Options options);
    ~OverwritePolicy();

    Policy policy() const;
    void setPolicy(Policy);

    /// returns the user's (or automatic) choice and the file name to write to or an empty string if overwriting was declined
    PolicyAndFileName obtainOverwritePermission(const QString &fileName, Options extraOptions = Options{});

private:
    class Private;
    const std::unique_ptr<Private> d;
};

class Output
{
public:
    virtual ~Output();

    virtual void setLabel(const QString &label) = 0;
    virtual QString label() const = 0;
    virtual std::shared_ptr<QIODevice> ioDevice() const = 0;
    virtual QString errorString() const = 0;
    virtual bool isFinalized() const = 0;
    virtual void finalize() = 0;
    virtual void cancel() = 0;
    virtual bool binaryOpt() const = 0;
    virtual void setBinaryOpt(bool value) = 0;
    /** Whether or not the output failed. */
    virtual bool failed() const
    {
        return false;
    }
    virtual QString fileName() const
    {
        return {};
    }

    static std::shared_ptr<Output> createFromFile(const QString &fileName, const std::shared_ptr<OverwritePolicy> &);
    static std::shared_ptr<Output> createFromFile(const QString &fileName, bool forceOverwrite);
    static std::shared_ptr<Output> createFromPipeDevice(assuan_fd_t fd, const QString &label);
    static std::shared_ptr<Output> createFromProcessStdIn(const QString &command, const QStringList &args, const QDir &workingDirectory);
#ifndef QT_NO_CLIPBOARD
    static std::shared_ptr<Output> createFromClipboard();
#endif
    static std::shared_ptr<Output> createFromByteArray(QByteArray *data, const QString &label);
};
}
