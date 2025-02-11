/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QMetaType>
#include <QString>
#include <QStringList>

#include <gpgme++/global.h> // GpgME::Protocol

#include <memory>
#include <vector>

class QDir;

namespace Kleo
{
class Input;
class Output;
}

namespace Kleo
{

class ArchiveDefinition
{
protected:
    ArchiveDefinition(const QString &id, const QString &label);

public:
    virtual ~ArchiveDefinition();

    enum ArgumentPassingMethod {
        CommandLine,
        NewlineSeparatedInputFile,
        NullSeparatedInputFile,

        NumArgumentPassingMethods
    };

    QString id() const
    {
        return m_id;
    }
    QString label() const
    {
        return m_label;
    }

    const QStringList &extensions(GpgME::Protocol p) const
    {
        checkProtocol(p);
        return m_extensions[p];
    }

    QString stripExtension(GpgME::Protocol p, const QString &filePath) const;

    std::shared_ptr<Input> createInputFromPackCommand(GpgME::Protocol p, const QStringList &files) const;
    ArgumentPassingMethod packCommandArgumentPassingMethod(GpgME::Protocol p) const
    {
        checkProtocol(p);
        return m_packCommandMethod[p];
    }

    std::shared_ptr<Output> createOutputFromUnpackCommand(GpgME::Protocol p, const QString &file, const QDir &wd) const;
    // unpack-command must use CommandLine ArgumentPassingMethod

    static QString installPath();
    static void setInstallPath(const QString &ip);

    static std::vector<std::shared_ptr<ArchiveDefinition>> getArchiveDefinitions();
    static std::vector<std::shared_ptr<ArchiveDefinition>> getArchiveDefinitions(QStringList &errors);

protected:
    void setPackCommandArgumentPassingMethod(GpgME::Protocol p, ArgumentPassingMethod method)
    {
        checkProtocol(p);
        m_packCommandMethod[p] = method;
    }
    void setExtensions(GpgME::Protocol p, const QStringList &extensions)
    {
        checkProtocol(p);
        m_extensions[p] = extensions;
    }

    void checkProtocol(GpgME::Protocol p) const;

private:
    virtual QString doGetPackCommand(GpgME::Protocol p) const = 0;
    virtual QString doGetUnpackCommand(GpgME::Protocol p) const = 0;
    virtual QStringList doGetPackArguments(GpgME::Protocol p, const QStringList &files) const = 0;
    virtual QStringList doGetUnpackArguments(GpgME::Protocol p, const QString &file) const = 0;

private:
    const QString m_id;
    const QString m_label;
    /*const*/ QStringList m_extensions[2];
    ArgumentPassingMethod m_packCommandMethod[2];
    // m_unpackCommandMethod[2] <- must always be CommandLine
};

}

Q_DECLARE_METATYPE(std::shared_ptr<Kleo::ArchiveDefinition>)
