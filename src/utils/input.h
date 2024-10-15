/* -*- mode: c++; c-basic-offset:4 -*-
    utils/input.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <assuan.h> // for assuan_fd_t

#include <memory>

class QIODevice;
class QString;
#include <QStringList>
class QByteArray;
class QFile;
class QDir;

namespace Kleo
{
class Output;
class Input
{
public:
    virtual ~Input();

    virtual QString label() const = 0;
    virtual void setLabel(const QString &label) = 0;
    virtual std::shared_ptr<QIODevice> ioDevice() const = 0;
    virtual unsigned int classification() const = 0;
    virtual unsigned long long size() const = 0;
    virtual QString errorString() const = 0;
    /** Whether or not the input failed. */
    virtual bool failed() const
    {
        return false;
    }

    void finalize(); // equivalent to ioDevice()->close();

    static std::shared_ptr<Input> createFromPipeDevice(assuan_fd_t fd, const QString &label);
    static std::shared_ptr<Input> createFromFile(const QString &filename, bool dummy = false);
    static std::shared_ptr<Input> createFromFile(const std::shared_ptr<QFile> &file);
    static std::shared_ptr<Input> createFromOutput(const std::shared_ptr<Output> &output); // implemented in output.cpp
    static std::shared_ptr<Input> createFromProcessStdOut(const QString &command, const QStringList &args, const QDir &workingDirectory);
    static std::shared_ptr<Input>
    createFromProcessStdOut(const QString &command, const QStringList &args, const QDir &workingDirectory, const QByteArray &stdin_);
#ifndef QT_NO_CLIPBOARD
    static std::shared_ptr<Input> createFromClipboard();
#endif
    static std::shared_ptr<Input> createFromByteArray(QByteArray *data, const QString &label);
};
}
