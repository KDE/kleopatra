/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "verifychecksumscontroller.h"

#include "checksumsutils_p.h"

#ifndef QT_NO_DIRMODEL

#include <crypto/gui/verifychecksumsdialog.h>

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <Libkleo/ChecksumDefinition>
#include <Libkleo/Classify>
#include <Libkleo/Stl_Util>

#include <KLocalizedString>

#include <QDir>
#include <QFileInfo>
#include <QMutex>
#include <QPointer>
#include <QProcess>
#include <QProgressDialog>
#include <QThread>

#include <gpg-error.h>

#include <deque>
#include <limits>
#include <set>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

#if 0
static QStringList fs_sort(QStringList l)
{
    int (*QString_compare)(const QString &, const QString &, Qt::CaseSensitivity) = &QString::compare;
    std::sort(l.begin(), l.end(),
              [](const QString &lhs, const QString &rhs) {
                return QString::compare(lhs, rhs, ChecksumsUtils::fs_cs) < 0;
              });
    return l;
}

static QStringList fs_intersect(QStringList l1, QStringList l2)
{
    int (*QString_compare)(const QString &, const QString &, Qt::CaseSensitivity) = &QString::compare;
    fs_sort(l1);
    fs_sort(l2);
    QStringList result;
    std::set_intersection(l1.begin(), l1.end(),
                          l2.begin(), l2.end(),
                          std::back_inserter(result),
                          [](const QString &lhs, const QString &rhs) {
                            return QString::compare(lhs, rhs, ChecksumsUtils::fs_cs) < 0;
                          });
    return result;
}
#endif

namespace
{
struct matches_none_of {
    const std::vector<QRegularExpression> m_regexps;
    explicit matches_none_of(const std::vector<QRegularExpression> &regexps)
        : m_regexps(regexps)
    {
    }
    bool operator()(const QString &s) const
    {
        return std::none_of(m_regexps.cbegin(), m_regexps.cend(), [&s](const QRegularExpression &rx) {
            return rx.match(s).hasMatch();
        });
    }
};
}

class VerifyChecksumsController::Private : public QThread
{
    Q_OBJECT
    friend class ::Kleo::Crypto::VerifyChecksumsController;
    VerifyChecksumsController *const q;

public:
    explicit Private(VerifyChecksumsController *qq);
    ~Private() override;

Q_SIGNALS:
    void baseDirectories(const QStringList &);
    void progress(int, int, const QString &);
    void status(const QString &file, Kleo::Crypto::Gui::VerifyChecksumsDialog::Status);

private:
    void slotOperationFinished()
    {
        if (dialog) {
            dialog->setProgress(100, 100);
            dialog->setErrors(errors);
        }

        if (!errors.empty())
            q->setLastError(gpg_error(GPG_ERR_GENERAL), errors.join(QLatin1Char('\n')));
        q->emitDoneOrError();
    }

private:
    void run() override;

private:
    QPointer<VerifyChecksumsDialog> dialog;
    mutable QMutex mutex;
    const std::vector<std::shared_ptr<ChecksumDefinition>> checksumDefinitions;
    QStringList files;
    QStringList errors;
    volatile bool canceled;
};

VerifyChecksumsController::Private::Private(VerifyChecksumsController *qq)
    : q(qq)
    , dialog()
    , mutex()
    , checksumDefinitions(ChecksumDefinition::getChecksumDefinitions())
    , files()
    , errors()
    , canceled(false)
{
    connect(this, &Private::progress, q, &Controller::progress);
    connect(this, SIGNAL(finished()), q, SLOT(slotOperationFinished()));
}

VerifyChecksumsController::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

VerifyChecksumsController::VerifyChecksumsController(QObject *p)
    : Controller(p)
    , d(new Private(this))
{
}

VerifyChecksumsController::VerifyChecksumsController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *p)
    : Controller(ctx, p)
    , d(new Private(this))
{
}

VerifyChecksumsController::~VerifyChecksumsController()
{
    qCDebug(KLEOPATRA_LOG);
}

void VerifyChecksumsController::setFiles(const QStringList &files)
{
    kleo_assert(!d->isRunning());
    kleo_assert(!files.empty());
    const QMutexLocker locker(&d->mutex);
    d->files = files;
}

void VerifyChecksumsController::start()
{
    {
        const QMutexLocker locker(&d->mutex);

        d->dialog = new VerifyChecksumsDialog;
        d->dialog->setAttribute(Qt::WA_DeleteOnClose);
        d->dialog->setWindowTitle(i18nc("@title:window", "Verify Checksum Results"));

        connect(d->dialog.data(), &VerifyChecksumsDialog::canceled, this, &VerifyChecksumsController::cancel);
        connect(d.get(), &Private::baseDirectories, d->dialog.data(), &VerifyChecksumsDialog::setBaseDirectories);
        connect(d.get(), &Private::progress, d->dialog.data(), &VerifyChecksumsDialog::setProgress);
        connect(d.get(), &Private::status, d->dialog.data(), &VerifyChecksumsDialog::setStatus);

        d->canceled = false;
        d->errors.clear();
    }

    d->start();

    d->dialog->show();
}

void VerifyChecksumsController::cancel()
{
    qCDebug(KLEOPATRA_LOG);
    const QMutexLocker locker(&d->mutex);
    d->canceled = true;
}

namespace
{

struct SumFile {
    QDir dir;
    QString sumFile;
    quint64 totalSize;
    std::shared_ptr<ChecksumDefinition> checksumDefinition;
};

}

static QStringList filter_checksum_files(QStringList l, const std::vector<QRegularExpression> &rxs)
{
    l.erase(std::remove_if(l.begin(), l.end(), matches_none_of(rxs)), l.end());
    return l;
}

static quint64 aggregate_size(const QDir &dir, const QStringList &files)
{
    quint64 n = 0;
    for (const QString &file : files) {
        n += QFileInfo(dir.absoluteFilePath(file)).size();
    }
    return n;
}

namespace
{
struct less_dir {
    bool operator()(const QDir &lhs, const QDir &rhs) const
    {
        return QString::compare(lhs.absolutePath(), rhs.absolutePath(), ChecksumsUtils::fs_cs) < 0;
    }
};
struct less_file {
    bool operator()(const QString &lhs, const QString &rhs) const
    {
        return QString::compare(lhs, rhs, ChecksumsUtils::fs_cs) < 0;
    }
};
struct sumfile_contains_file {
    const QDir dir;
    const QString fileName;
    sumfile_contains_file(const QDir &dir_, const QString &fileName_)
        : dir(dir_)
        , fileName(fileName_)
    {
    }
    bool operator()(const QString &sumFile) const
    {
        const std::vector<ChecksumsUtils::File> files = ChecksumsUtils::parse_sum_file(dir.absoluteFilePath(sumFile));
        qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files:      found " << files.size() << " files listed in " << qPrintable(dir.absoluteFilePath(sumFile));
        for (const ChecksumsUtils::File &file : files) {
            const bool isSameFileName = (QString::compare(file.name, fileName, ChecksumsUtils::fs_cs) == 0);
            qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files:        " << qPrintable(file.name) << " == " << qPrintable(fileName) << " ? " << isSameFileName;
            if (isSameFileName) {
                return true;
            }
        }
        return false;
    }
};
}

// IF is_dir(file)
//   add all sumfiles \in dir(file)
//   inputs.prepend( all dirs \in dir(file) )
// ELSE IF is_sum_file(file)
//   add
// ELSE IF \exists sumfile in dir(file) \where sumfile \contains file
//   add sumfile
// ELSE
//   error: no checksum found for "file"

static QStringList find_base_directories(const QStringList &files)
{
    // Step 1: find base dirs:

    std::set<QDir, less_dir> dirs;
    for (const QString &file : files) {
        const QFileInfo fi(file);
        const QDir dir = fi.isDir() ? QDir(file) : fi.dir();
        dirs.insert(dir);
    }

    // Step 1a: collapse direct child directories

    bool changed;
    do {
        changed = false;
        auto it = dirs.begin();
        while (it != dirs.end()) {
            QDir dir = *it;
            if (dir.cdUp() && dirs.count(dir)) {
                dirs.erase(it++);
                changed = true;
            } else {
                ++it;
            }
        }
    } while (changed);

    QStringList rv;
    rv.reserve(dirs.size());
    std::transform(dirs.cbegin(), dirs.cend(), std::back_inserter(rv), std::mem_fn(&QDir::absolutePath));
    return rv;
}

static std::vector<SumFile> find_sums_by_input_files(const QStringList &files,
                                                     QStringList &errors,
                                                     const std::function<void(int)> &progress,
                                                     const std::vector<std::shared_ptr<ChecksumDefinition>> &checksumDefinitions)
{
    const std::vector<QRegularExpression> patterns = ChecksumsUtils::get_patterns(checksumDefinitions);

    const ChecksumsUtils::matches_any is_sum_file(patterns);

    std::map<QDir, std::set<QString, less_file>, less_dir> dirs2sums;

    // Step 1: find the sumfiles we need to check:

    std::deque<QString> inputs(files.begin(), files.end());

    int i = 0;
    while (!inputs.empty()) {
        const QString file = inputs.front();
        qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files: considering " << qPrintable(file);
        inputs.pop_front();
        const QFileInfo fi(file);
        const QString fileName = fi.fileName();
        if (fi.isDir()) {
            qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files:   it's a directory";
            QDir dir(file);
            const QStringList sumfiles = filter_checksum_files(dir.entryList(QDir::Files), patterns);
            qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files:   found " << sumfiles.size()
                                   << " sum files: " << qPrintable(sumfiles.join(QLatin1StringView(", ")));
            dirs2sums[dir].insert(sumfiles.begin(), sumfiles.end());
            const QStringList dirs = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
            qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files:   found " << dirs.size() << " subdirs, prepending";
            std::transform(dirs.cbegin(), dirs.cend(), std::inserter(inputs, inputs.begin()), [&dir](const QString &path) {
                return dir.absoluteFilePath(path);
            });
        } else if (is_sum_file(fileName)) {
            qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files:   it's a sum file";
            dirs2sums[fi.dir()].insert(fileName);
        } else {
            qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files:   it's something else; checking whether we'll find a sumfile for it...";
            const QDir dir = fi.dir();
            const QStringList sumfiles = filter_checksum_files(dir.entryList(QDir::Files), patterns);
            qCDebug(KLEOPATRA_LOG) << "find_sums_by_input_files:   found " << sumfiles.size()
                                   << " potential sumfiles: " << qPrintable(sumfiles.join(QLatin1StringView(", ")));
            const auto it = std::find_if(sumfiles.cbegin(), sumfiles.cend(), sumfile_contains_file(dir, fileName));
            if (it == sumfiles.end()) {
                errors.push_back(i18n("Cannot find checksums file for file %1", file));
            } else {
                dirs2sums[dir].insert(*it);
            }
        }
        if (progress) {
            progress(++i);
        }
    }

    // Step 2: convert into vector<SumFile>:

    std::vector<SumFile> sumfiles;
    sumfiles.reserve(dirs2sums.size());

    for (auto it = dirs2sums.begin(), end = dirs2sums.end(); it != end; ++it) {
        if (it->second.empty()) {
            continue;
        }

        const QDir &dir = it->first;

        for (const QString &sumFileName : std::as_const(it->second)) {
            const std::vector<ChecksumsUtils::File> summedfiles = ChecksumsUtils::parse_sum_file(dir.absoluteFilePath(sumFileName));
            QStringList files;
            files.reserve(summedfiles.size());
            std::transform(summedfiles.cbegin(), summedfiles.cend(), std::back_inserter(files), std::mem_fn(&ChecksumsUtils::File::name));
            const SumFile sumFile = {
                it->first,
                sumFileName,
                aggregate_size(it->first, files),
                ChecksumsUtils::filename2definition(sumFileName, checksumDefinitions),
            };
            sumfiles.push_back(sumFile);
        }

        if (progress) {
            progress(++i);
        }
    }
    return sumfiles;
}

static QStringList c_lang_environment()
{
    static const QRegularExpression re(QRegularExpression::anchoredPattern(u"LANG=.*"), ChecksumsUtils::s_regex_cs);
    QStringList env = QProcess::systemEnvironment();
    env.erase(std::remove_if(env.begin(),
                             env.end(),
                             [](const QString &str) {
                                 return re.match(str).hasMatch();
                             }),
              env.end());
    env.push_back(QStringLiteral("LANG=C"));
    return env;
}

static const struct {
    const char *string;
    VerifyChecksumsDialog::Status status;
} statusStrings[] = {
    {"OK", VerifyChecksumsDialog::OK},
    {"FAILED", VerifyChecksumsDialog::Failed},
};
static const size_t numStatusStrings = sizeof statusStrings / sizeof *statusStrings;

static VerifyChecksumsDialog::Status string2status(const QByteArray &str)
{
    for (unsigned int i = 0; i < numStatusStrings; ++i)
        if (str == statusStrings[i].string) {
            return statusStrings[i].status;
        }
    return VerifyChecksumsDialog::Unknown;
}

static QString
process(const SumFile &sumFile, bool *fatal, const QStringList &env, const std::function<void(const QString &, VerifyChecksumsDialog::Status)> &status)
{
    QProcess p;
    p.setEnvironment(env);
    p.setWorkingDirectory(sumFile.dir.absolutePath());
    p.setReadChannel(QProcess::StandardOutput);

    const QString absFilePath = sumFile.dir.absoluteFilePath(sumFile.sumFile);

    const QString program = sumFile.checksumDefinition->verifyCommand();
    sumFile.checksumDefinition->startVerifyCommand(&p, QStringList(absFilePath));

    QByteArray remainder; // used for filenames with newlines in them
    while (p.state() != QProcess::NotRunning) {
        p.waitForReadyRead();
        while (p.canReadLine()) {
            const QByteArray line = p.readLine();
            const int colonIdx = line.lastIndexOf(':');
            if (colonIdx < 0) {
                remainder += line; // no colon -> probably filename with a newline
                continue;
            }
#ifdef Q_OS_WIN
            const QString file = QString::fromUtf8(remainder + line.left(colonIdx));
#else
            const QString file = QFile::decodeName(remainder + line.left(colonIdx));
#endif
            remainder.clear();
            const VerifyChecksumsDialog::Status result = string2status(line.mid(colonIdx + 1).trimmed());
            status(sumFile.dir.absoluteFilePath(file), result);
        }
    }
    qCDebug(KLEOPATRA_LOG) << "[" << &p << "] Exit code " << p.exitCode();

    if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0) {
        if (fatal && p.error() == QProcess::FailedToStart) {
            *fatal = true;
        }
        if (p.error() == QProcess::UnknownError)
            return i18n("Error while running %1: %2", program, QString::fromLocal8Bit(p.readAllStandardError().trimmed().constData()));
        else {
            return i18n("Failed to execute %1: %2", program, p.errorString());
        }
    }

    return QString();
}

namespace
{
static QDebug operator<<(QDebug s, const SumFile &sum)
{
    return s << "SumFile(" << sum.dir << "->" << sum.sumFile << "<-(" << sum.totalSize << ')' << ")\n";
}
}

void VerifyChecksumsController::Private::run()
{
    QMutexLocker locker(&mutex);

    const QStringList files = this->files;
    const std::vector<std::shared_ptr<ChecksumDefinition>> checksumDefinitions = this->checksumDefinitions;

    locker.unlock();

    QStringList errors;

    //
    // Step 0: find base directories:
    //

    Q_EMIT baseDirectories(find_base_directories(files));

    //
    // Step 1: build a list of work to do (no progress):
    //

    const QString scanning = i18n("Scanning directories...");
    Q_EMIT progress(0, 0, scanning);

    const auto progressCb = [this, scanning](int arg) {
        Q_EMIT progress(arg, 0, scanning);
    };
    const auto statusCb = [this](const QString &str, VerifyChecksumsDialog::Status st) {
        Q_EMIT status(str, st);
    };

    const std::vector<SumFile> sumfiles = find_sums_by_input_files(files, errors, progressCb, checksumDefinitions);

    for (const SumFile &sumfile : sumfiles) {
        qCDebug(KLEOPATRA_LOG) << sumfile;
    }

    if (!canceled) {
        Q_EMIT progress(0, 0, i18n("Calculating total size..."));

        const quint64 total = kdtools::accumulate_transform(sumfiles.cbegin(), sumfiles.cend(), std::mem_fn(&SumFile::totalSize), Q_UINT64_C(0));

        if (!canceled) {
            //
            // Step 2: perform work (with progress reporting):
            //

            const QStringList env = c_lang_environment();

            // re-scale 'total' to fit into ints (wish QProgressDialog would use quint64...)
            const quint64 factor = total / std::numeric_limits<int>::max() + 1;

            quint64 done = 0;
            for (const SumFile &sumFile : sumfiles) {
                Q_EMIT progress(done / factor, total / factor, i18n("Verifying checksums (%2) in %1", sumFile.checksumDefinition->label(), sumFile.dir.path()));
                bool fatal = false;
                const QString error = process(sumFile, &fatal, env, statusCb);
                if (!error.isEmpty()) {
                    errors.push_back(error);
                }
                done += sumFile.totalSize;
                if (fatal || canceled) {
                    break;
                }
            }
            Q_EMIT progress(done / factor, total / factor, i18n("Done."));
        }
    }

    locker.relock();

    this->errors = errors;

    // mutex unlocked by QMutexLocker
}

#include "moc_verifychecksumscontroller.cpp"
#include "verifychecksumscontroller.moc"

#endif // QT_NO_DIRMODEL
