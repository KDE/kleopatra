/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009, 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "archivedefinition.h"

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>
#include <utils/path-helper.h>

#include <gpgme++/exception.h>

#include "kleopatra_debug.h"
#include <KConfig>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>
#include <KShell>

#include <QCoreApplication>
#include <QDir>
#include <QMutex>
#include <QRegularExpression>

#include <QStandardPaths>

using namespace GpgME;
using namespace Kleo;

static QMutex installPathMutex;
Q_GLOBAL_STATIC(QString, _installPath)
QString ArchiveDefinition::installPath()
{
    const QMutexLocker locker(&installPathMutex);
    QString *const ip = _installPath();
    if (ip->isEmpty()) {
        if (QCoreApplication::instance()) {
            *ip = QCoreApplication::applicationDirPath();
        } else {
            qCWarning(KLEOPATRA_LOG) << "called before QCoreApplication was constructed";
        }
    }
    return *ip;
}
void ArchiveDefinition::setInstallPath(const QString &ip)
{
    const QMutexLocker locker(&installPathMutex);
    *_installPath() = ip;
}

// Archive Definition #N groups
static const QLatin1StringView ID_ENTRY("id");
static const QLatin1StringView NAME_ENTRY("Name");
static const QLatin1StringView PACK_COMMAND_ENTRY("pack-command");
static const QLatin1StringView PACK_COMMAND_OPENPGP_ENTRY("pack-command-openpgp");
static const QLatin1StringView PACK_COMMAND_CMS_ENTRY("pack-command-cms");
static const QLatin1StringView UNPACK_COMMAND_ENTRY("unpack-command");
static const QLatin1StringView UNPACK_COMMAND_OPENPGP_ENTRY("unpack-command-openpgp");
static const QLatin1StringView UNPACK_COMMAND_CMS_ENTRY("unpack-command-cms");
static const QLatin1StringView EXTENSIONS_ENTRY("extensions");
static const QLatin1StringView EXTENSIONS_OPENPGP_ENTRY("extensions-openpgp");
static const QLatin1StringView EXTENSIONS_CMS_ENTRY("extensions-cms");
static const QLatin1StringView FILE_PLACEHOLDER("%f");
static const QLatin1StringView FILE_PLACEHOLDER_7BIT("%F");
static const QLatin1StringView INSTALLPATH_PLACEHOLDER("%I");
static const QLatin1StringView NULL_SEPARATED_STDIN_INDICATOR("0|");
static const QLatin1Char NEWLINE_SEPARATED_STDIN_INDICATOR('|');

namespace
{

class ArchiveDefinitionError : public Kleo::Exception
{
    const QString m_id;

public:
    ArchiveDefinitionError(const QString &id, const QString &message)
        : Kleo::Exception(GPG_ERR_INV_PARAMETER, i18n("Error in archive definition %1: %2", id, message), MessageOnly)
        , m_id(id)
    {
    }
    ~ArchiveDefinitionError() throw() override
    {
    }

    const QString &archiveDefinitionId() const
    {
        return m_id;
    }
};

}

static QString try_extensions(const QString &path)
{
    static const char exts[][4] = {
        "",
        "exe",
        "bat",
        "bin",
        "cmd",
    };
    static const size_t numExts = sizeof exts / sizeof *exts;
    for (unsigned int i = 0; i < numExts; ++i) {
        const QFileInfo fi(path + QLatin1Char('.') + QLatin1StringView(exts[i]));
        if (fi.exists()) {
            return fi.filePath();
        }
    }
    return QString();
}

static void parse_command(QString cmdline,
                          const QString &id,
                          const QString &whichCommand,
                          QString *command,
                          QStringList *prefix,
                          QStringList *suffix,
                          ArchiveDefinition::ArgumentPassingMethod *method,
                          bool parseFilePlaceholder)
{
    Q_ASSERT(prefix);
    Q_ASSERT(suffix);
    Q_ASSERT(method);

    KShell::Errors errors;
    QStringList l;

    if (cmdline.startsWith(NULL_SEPARATED_STDIN_INDICATOR)) {
        *method = ArchiveDefinition::NullSeparatedInputFile;
        cmdline.remove(0, 2);
    } else if (cmdline.startsWith(NEWLINE_SEPARATED_STDIN_INDICATOR)) {
        *method = ArchiveDefinition::NewlineSeparatedInputFile;
        cmdline.remove(0, 1);
    } else {
        *method = ArchiveDefinition::CommandLine;
    }
    if (*method != ArchiveDefinition::CommandLine && cmdline.contains(FILE_PLACEHOLDER)) {
        throw ArchiveDefinitionError(id, i18n("Cannot use both %f and | in '%1'", whichCommand));
    }
    cmdline.replace(FILE_PLACEHOLDER, QLatin1StringView("__files_go_here__"))
        .replace(INSTALLPATH_PLACEHOLDER, QStringLiteral("__path_goes_here__"))
        .replace(FILE_PLACEHOLDER_7BIT, QStringLiteral("__file7Bit_go_here__"));
    l = KShell::splitArgs(cmdline, KShell::AbortOnMeta | KShell::TildeExpand, &errors);
    l = l.replaceInStrings(QStringLiteral("__files_go_here__"), FILE_PLACEHOLDER);
    l = l.replaceInStrings(QStringLiteral("__file7Bit_go_here__"), FILE_PLACEHOLDER_7BIT);
    if (l.indexOf(QRegularExpression(QLatin1StringView(".*__path_goes_here__.*"))) >= 0) {
        l = l.replaceInStrings(QStringLiteral("__path_goes_here__"), ArchiveDefinition::installPath());
    }
    if (errors == KShell::BadQuoting) {
        throw ArchiveDefinitionError(id, i18n("Quoting error in '%1' entry", whichCommand));
    }
    if (errors == KShell::FoundMeta) {
        throw ArchiveDefinitionError(id, i18n("'%1' too complex (would need shell)", whichCommand));
    }
    qCDebug(KLEOPATRA_LOG) << "ArchiveDefinition[" << id << ']' << l;
    if (l.empty()) {
        throw ArchiveDefinitionError(id, i18n("'%1' entry is empty/missing", whichCommand));
    }
    const QFileInfo fi1(l.front());
    if (fi1.isAbsolute()) {
        *command = try_extensions(l.front());
    } else {
        *command = QStandardPaths::findExecutable(fi1.fileName());
    }
    if (command->isEmpty()) {
        throw ArchiveDefinitionError(id, i18n("'%1' empty or not found", whichCommand));
    }
    if (parseFilePlaceholder) {
        const int idx1 = l.indexOf(FILE_PLACEHOLDER);
        if (idx1 < 0) {
            // none -> append
            *prefix = l.mid(1);
        } else {
            *prefix = l.mid(1, idx1 - 1);
            *suffix = l.mid(idx1 + 1);
        }
    } else {
        *prefix = l.mid(1);
    }
    switch (*method) {
    case ArchiveDefinition::CommandLine:
        qCDebug(KLEOPATRA_LOG) << "ArchiveDefinition[" << id << ']' << *command << *prefix << FILE_PLACEHOLDER << *suffix;
        break;
    case ArchiveDefinition::NewlineSeparatedInputFile:
        qCDebug(KLEOPATRA_LOG) << "ArchiveDefinition[" << id << ']' << "find | " << *command << *prefix;
        break;
    case ArchiveDefinition::NullSeparatedInputFile:
        qCDebug(KLEOPATRA_LOG) << "ArchiveDefinition[" << id << ']' << "find -print0 | " << *command << *prefix;
        break;
    case ArchiveDefinition::NumArgumentPassingMethods:
        Q_ASSERT(!"Should not happen");
        break;
    }
}

namespace
{

class KConfigBasedArchiveDefinition : public ArchiveDefinition
{
public:
    explicit KConfigBasedArchiveDefinition(const KConfigGroup &group)
        : ArchiveDefinition(group.readEntryUntranslated(ID_ENTRY), group.readEntry(NAME_ENTRY))
    {
        if (id().isEmpty()) {
            throw ArchiveDefinitionError(group.name(), i18n("'%1' entry is empty/missing", ID_ENTRY));
        }

        QStringList extensions;
        QString extensionsKey;

        // extensions(-openpgp)
        if (group.hasKey(EXTENSIONS_OPENPGP_ENTRY)) {
            extensionsKey = EXTENSIONS_OPENPGP_ENTRY;
        } else {
            extensionsKey = EXTENSIONS_ENTRY;
        }
        extensions = group.readEntry(extensionsKey, QStringList());
        if (extensions.empty()) {
            throw ArchiveDefinitionError(id(), i18n("'%1' entry is empty/missing", extensionsKey));
        }
        setExtensions(OpenPGP, extensions);

        // extensions(-cms)
        if (group.hasKey(EXTENSIONS_CMS_ENTRY)) {
            extensionsKey = EXTENSIONS_CMS_ENTRY;
        } else {
            extensionsKey = EXTENSIONS_ENTRY;
        }
        extensions = group.readEntry(extensionsKey, QStringList());
        if (extensions.empty()) {
            throw ArchiveDefinitionError(id(), i18n("'%1' entry is empty/missing", extensionsKey));
        }
        setExtensions(CMS, extensions);

        ArgumentPassingMethod method;

        // pack-command(-openpgp)
        if (group.hasKey(PACK_COMMAND_OPENPGP_ENTRY))
            parse_command(group.readEntry(PACK_COMMAND_OPENPGP_ENTRY),
                          id(),
                          PACK_COMMAND_OPENPGP_ENTRY,
                          &m_packCommand[OpenPGP],
                          &m_packPrefixArguments[OpenPGP],
                          &m_packPostfixArguments[OpenPGP],
                          &method,
                          true);
        else
            parse_command(group.readEntry(PACK_COMMAND_ENTRY),
                          id(),
                          PACK_COMMAND_ENTRY,
                          &m_packCommand[OpenPGP],
                          &m_packPrefixArguments[OpenPGP],
                          &m_packPostfixArguments[OpenPGP],
                          &method,
                          true);
        setPackCommandArgumentPassingMethod(OpenPGP, method);

        // pack-command(-cms)
        if (group.hasKey(PACK_COMMAND_CMS_ENTRY))
            parse_command(group.readEntry(PACK_COMMAND_CMS_ENTRY),
                          id(),
                          PACK_COMMAND_CMS_ENTRY,
                          &m_packCommand[CMS],
                          &m_packPrefixArguments[CMS],
                          &m_packPostfixArguments[CMS],
                          &method,
                          true);
        else
            parse_command(group.readEntry(PACK_COMMAND_ENTRY),
                          id(),
                          PACK_COMMAND_ENTRY,
                          &m_packCommand[CMS],
                          &m_packPrefixArguments[CMS],
                          &m_packPostfixArguments[CMS],
                          &method,
                          true);
        setPackCommandArgumentPassingMethod(CMS, method);

        QStringList dummy;

        // unpack-command(-openpgp)
        if (group.hasKey(UNPACK_COMMAND_OPENPGP_ENTRY))
            parse_command(group.readEntry(UNPACK_COMMAND_OPENPGP_ENTRY),
                          id(),
                          UNPACK_COMMAND_OPENPGP_ENTRY,
                          &m_unpackCommand[OpenPGP],
                          &m_unpackArguments[OpenPGP],
                          &dummy,
                          &method,
                          false);
        else
            parse_command(group.readEntry(UNPACK_COMMAND_ENTRY),
                          id(),
                          UNPACK_COMMAND_ENTRY,
                          &m_unpackCommand[OpenPGP],
                          &m_unpackArguments[OpenPGP],
                          &dummy,
                          &method,
                          false);
        if (method != CommandLine) {
            throw ArchiveDefinitionError(id(), i18n("cannot use argument passing on standard input for unpack-command"));
        }

        // unpack-command(-cms)
        if (group.hasKey(UNPACK_COMMAND_CMS_ENTRY))
            parse_command(group.readEntry(UNPACK_COMMAND_CMS_ENTRY),
                          id(),
                          UNPACK_COMMAND_CMS_ENTRY,
                          &m_unpackCommand[CMS],
                          &m_unpackArguments[CMS],
                          &dummy,
                          &method,
                          false);
        else
            parse_command(group.readEntry(UNPACK_COMMAND_ENTRY),
                          id(),
                          UNPACK_COMMAND_ENTRY,
                          &m_unpackCommand[CMS],
                          &m_unpackArguments[CMS],
                          &dummy,
                          &method,
                          false);
        if (method != CommandLine) {
            throw ArchiveDefinitionError(id(), i18n("cannot use argument passing on standard input for unpack-command"));
        }
    }

private:
    QString doGetPackCommand(GpgME::Protocol p) const override
    {
        return m_packCommand[p];
    }
    QString doGetUnpackCommand(GpgME::Protocol p) const override
    {
        return m_unpackCommand[p];
    }
    QStringList doGetPackArguments(GpgME::Protocol p, const QStringList &files) const override
    {
        return m_packPrefixArguments[p] + files + m_packPostfixArguments[p];
    }
    QStringList doGetUnpackArguments(GpgME::Protocol p, const QString &file) const override
    {
        QStringList copy = m_unpackArguments[p];
        if (copy.contains(FILE_PLACEHOLDER_7BIT)) {
            /* This is a crutch for missing a way to provide Unicode arguments
             * to gpgtar unless gpgtar offers a unicode interface we have
             * no defined way to provide non 7Bit arguments. So we filter out
             * the chars and replace them by _ to avoid completely broken
             * folder names when unpacking. This is only relevant for the
             * unpacked folder and does not effect files in the archive. */
            const QRegularExpression non7Bit(QLatin1StringView(R"([^\x{0000}-\x{007F}])"));
            QString underscore_filename = file;
            underscore_filename.replace(non7Bit, QStringLiteral("_"));
            copy.replaceInStrings(FILE_PLACEHOLDER_7BIT, underscore_filename);
        }
        copy.replaceInStrings(FILE_PLACEHOLDER, file);
        return copy;
    }

private:
    QString m_packCommand[2], m_unpackCommand[2];
    QStringList m_packPrefixArguments[2], m_packPostfixArguments[2];
    QStringList m_unpackArguments[2];
};

}

ArchiveDefinition::ArchiveDefinition(const QString &id, const QString &label)
    : m_id(id)
    , m_label(label)
{
    m_packCommandMethod[GpgME::OpenPGP] = m_packCommandMethod[GpgME::CMS] = CommandLine;
}

ArchiveDefinition::~ArchiveDefinition()
{
}

QString ArchiveDefinition::stripExtension(GpgME::Protocol p, const QString &filePath) const
{
    checkProtocol(p);
    for (const auto &ext : std::as_const(m_extensions[p])) {
        if (filePath.endsWith(QLatin1Char('.') + ext)) {
            return filePath.chopped(ext.size() + 1);
        }
    }
    return filePath;
}

static QByteArray make_input(const QStringList &files, char sep)
{
    QByteArray result;
    for (const QString &file : files) {
#ifdef Q_OS_WIN
        // As encoding is more complicated on windows with different
        // 8 bit codepages we always use UTF-8 here and add this as an
        // option in the libkleopatrarc.desktop archive definition.
        result += file.toUtf8();
#else
        result += QFile::encodeName(file);
#endif
        result += sep;
    }
    return result;
}

std::shared_ptr<Input> ArchiveDefinition::createInputFromPackCommand(GpgME::Protocol p, const QStringList &files) const
{
    checkProtocol(p);
    const QString base = heuristicBaseDirectory(files);
    if (base.isEmpty()) {
        throw Kleo::Exception(GPG_ERR_CONFLICT, i18n("Cannot find common base directory for these files:\n%1", files.join(QLatin1Char('\n'))));
    }
    qCDebug(KLEOPATRA_LOG) << "heuristicBaseDirectory(" << files << ") ->" << base;
    const QStringList relative = makeRelativeTo(base, files);
    qCDebug(KLEOPATRA_LOG) << "relative" << relative;
    switch (m_packCommandMethod[p]) {
    case CommandLine:
        return Input::createFromProcessStdOut(doGetPackCommand(p), doGetPackArguments(p, relative), QDir(base));
    case NewlineSeparatedInputFile:
        return Input::createFromProcessStdOut(doGetPackCommand(p), doGetPackArguments(p, QStringList()), QDir(base), make_input(relative, '\n'));
    case NullSeparatedInputFile:
        return Input::createFromProcessStdOut(doGetPackCommand(p), doGetPackArguments(p, QStringList()), QDir(base), make_input(relative, '\0'));
    case NumArgumentPassingMethods:
        Q_ASSERT(!"Should not happen");
    }
    return std::shared_ptr<Input>(); // make compiler happy
}

std::shared_ptr<Output> ArchiveDefinition::createOutputFromUnpackCommand(GpgME::Protocol p, const QString &file, const QDir &wd) const
{
    checkProtocol(p);
    const QFileInfo fi(file);
    return Output::createFromProcessStdIn(doGetUnpackCommand(p), doGetUnpackArguments(p, fi.absoluteFilePath()), wd, file);
}

// static
std::vector<std::shared_ptr<ArchiveDefinition>> ArchiveDefinition::getArchiveDefinitions()
{
    QStringList errors;
    return getArchiveDefinitions(errors);
}

// static
std::vector<std::shared_ptr<ArchiveDefinition>> ArchiveDefinition::getArchiveDefinitions(QStringList &errors)
{
    std::vector<std::shared_ptr<ArchiveDefinition>> result;
    KSharedConfigPtr config = KSharedConfig::openConfig(QStringLiteral("libkleopatrarc"));
    const QStringList groups = config->groupList().filter(QRegularExpression(QStringLiteral("^Archive Definition #")));
    result.reserve(groups.size());
    for (const QString &group : groups)
        try {
            const std::shared_ptr<ArchiveDefinition> ad(new KConfigBasedArchiveDefinition(KConfigGroup(config, group)));
            result.push_back(ad);
        } catch (const std::exception &e) {
            qCDebug(KLEOPATRA_LOG) << e.what();
            errors.push_back(QString::fromLocal8Bit(e.what()));
        } catch (...) {
            errors.push_back(i18n("Caught unknown exception in group %1", group));
        }
    return result;
}

void ArchiveDefinition::checkProtocol(GpgME::Protocol p) const
{
    kleo_assert(p == GpgME::OpenPGP || p == GpgME::CMS);
}
