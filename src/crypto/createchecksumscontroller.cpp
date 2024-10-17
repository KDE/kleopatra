/* -*- mode: c++; c-basic-offset:4 -*-
    crypto/createchecksumscontroller.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "checksumsutils_p.h"
#include "createchecksumscontroller.h"

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <Libkleo/ChecksumDefinition>
#include <Libkleo/Classify>
#include <Libkleo/Stl_Util>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>
#include <QTemporaryFile>

#include <QDialog>
#include <QDialogButtonBox>
#include <QLabel>
#include <QListWidget>
#include <QVBoxLayout>

#include <QDir>
#include <QFileInfo>
#include <QMutex>
#include <QPointer>
#include <QProcess>
#include <QProgressDialog>
#include <QThread>

#include <gpg-error.h>

#include <deque>
#include <functional>
#include <limits>
#include <map>

using namespace Kleo;
using namespace Kleo::Crypto;

namespace
{

class ResultDialog : public QDialog
{
    Q_OBJECT
public:
    ResultDialog(const QStringList &created, const QStringList &errors, QWidget *parent = nullptr, Qt::WindowFlags f = {})
        : QDialog(parent, f)
        , createdLB(created.empty() ? i18nc("@info", "No checksum files have been created.")
                                    : i18nc("@info", "These checksum files have been successfully created:"),
                    this)
        , createdLW(this)
        , errorsLB(errors.empty() ? i18nc("@info", "There were no errors.") //
                                  : i18nc("@info", "The following errors were encountered:"),
                   this)
        , errorsLW(this)
        , buttonBox(QDialogButtonBox::Ok, Qt::Horizontal, this)
        , vlay(this)
    {
        Q_SET_OBJECT_NAME(createdLB);
        Q_SET_OBJECT_NAME(createdLW);
        Q_SET_OBJECT_NAME(errorsLB);
        Q_SET_OBJECT_NAME(errorsLW);
        Q_SET_OBJECT_NAME(buttonBox);
        Q_SET_OBJECT_NAME(vlay);

        createdLW.addItems(created);
        QRect r;
        for (int i = 0; i < created.size(); ++i) {
            r = r.united(createdLW.visualRect(createdLW.model()->index(0, i)));
        }
        createdLW.setMinimumWidth(qMin(1024, r.width() + 4 * createdLW.frameWidth()));

        errorsLW.addItems(errors);

        vlay.addWidget(&createdLB);
        vlay.addWidget(&createdLW, 1);
        vlay.addWidget(&errorsLB);
        vlay.addWidget(&errorsLW, 1);
        vlay.addWidget(&buttonBox);

        if (created.empty()) {
            createdLW.hide();
        }
        if (errors.empty()) {
            errorsLW.hide();
        }

        connect(&buttonBox, &QDialogButtonBox::accepted, this, &ResultDialog::accept);
        connect(&buttonBox, &QDialogButtonBox::rejected, this, &ResultDialog::reject);
        readConfig();
    }
    ~ResultDialog() override
    {
        writeConfig();
    }

    void readConfig()
    {
        KConfigGroup dialog(KSharedConfig::openStateConfig(), QStringLiteral("ResultDialog"));
        const QSize size = dialog.readEntry("Size", QSize(600, 400));
        if (size.isValid()) {
            resize(size);
        }
    }
    void writeConfig()
    {
        KConfigGroup dialog(KSharedConfig::openStateConfig(), QStringLiteral("ResultDialog"));
        dialog.writeEntry("Size", size());
        dialog.sync();
    }

private:
    QLabel createdLB;
    QListWidget createdLW;
    QLabel errorsLB;
    QListWidget errorsLW;
    QDialogButtonBox buttonBox;
    QVBoxLayout vlay;
};

}

static QStringList fs_sort(QStringList l)
{
    std::sort(l.begin(), l.end(), [](const QString &lhs, const QString &rhs) {
        return QString::compare(lhs, rhs, ChecksumsUtils::fs_cs) < 0;
    });
    return l;
}

static QStringList fs_intersect(QStringList l1, QStringList l2)
{
    fs_sort(l1);
    fs_sort(l2);
    QStringList result;
    std::set_intersection(l1.begin(), l1.end(), l2.begin(), l2.end(), std::back_inserter(result), [](const QString &lhs, const QString &rhs) {
        return QString::compare(lhs, rhs, ChecksumsUtils::fs_cs) < 0;
    });
    return result;
}

class CreateChecksumsController::Private : public QThread
{
    Q_OBJECT
    friend class ::Kleo::Crypto::CreateChecksumsController;
    CreateChecksumsController *const q;

public:
    explicit Private(CreateChecksumsController *qq);
    ~Private() override;

Q_SIGNALS:
    void progress(int, int, const QString &);

private:
    void slotOperationFinished()
    {
#ifndef QT_NO_PROGRESSDIALOG
        if (progressDialog) {
            progressDialog->setValue(progressDialog->maximum());
            progressDialog->close();
        }
#endif // QT_NO_PROGRESSDIALOG
        auto const dlg = new ResultDialog(created, errors);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        q->bringToForeground(dlg);
        if (!errors.empty())
            q->setLastError(gpg_error(GPG_ERR_GENERAL), errors.join(QLatin1Char('\n')));
        q->emitDoneOrError();
    }
    void slotProgress(int current, int total, const QString &what)
    {
        qCDebug(KLEOPATRA_LOG) << "progress: " << current << "/" << total << ": " << qPrintable(what);
#ifndef QT_NO_PROGRESSDIALOG
        if (!progressDialog) {
            return;
        }
        progressDialog->setMaximum(total);
        progressDialog->setValue(current);
        progressDialog->setLabelText(what);
#endif // QT_NO_PROGRESSDIALOG
    }

private:
    void run() override;

private:
#ifndef QT_NO_PROGRESSDIALOG
    QPointer<QProgressDialog> progressDialog;
#endif
    mutable QMutex mutex;
    const std::vector<std::shared_ptr<ChecksumDefinition>> checksumDefinitions;
    std::shared_ptr<ChecksumDefinition> checksumDefinition;
    QStringList files;
    QStringList errors, created;
    bool allowAddition;
    volatile bool canceled;
};

CreateChecksumsController::Private::Private(CreateChecksumsController *qq)
    : q(qq)
    ,
#ifndef QT_NO_PROGRESSDIALOG
    progressDialog()
    ,
#endif
    mutex()
    , checksumDefinitions(ChecksumDefinition::getChecksumDefinitions())
    , checksumDefinition(ChecksumDefinition::getDefaultChecksumDefinition(checksumDefinitions))
    , files()
    , errors()
    , created()
    , allowAddition(false)
    , canceled(false)
{
    connect(this, SIGNAL(progress(int, int, QString)), q, SLOT(slotProgress(int, int, QString)));
    connect(this, &Private::progress, q, &Controller::progress);
    connect(this, SIGNAL(finished()), q, SLOT(slotOperationFinished()));
}

CreateChecksumsController::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

CreateChecksumsController::CreateChecksumsController(QObject *p)
    : Controller(p)
    , d(new Private(this))
{
}

CreateChecksumsController::CreateChecksumsController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *p)
    : Controller(ctx, p)
    , d(new Private(this))
{
}

CreateChecksumsController::~CreateChecksumsController()
{
    qCDebug(KLEOPATRA_LOG);
}

void CreateChecksumsController::setFiles(const QStringList &files)
{
    kleo_assert(!d->isRunning());
    kleo_assert(!files.empty());
    const std::vector<QRegularExpression> patterns = ChecksumsUtils::get_patterns(d->checksumDefinitions);
    if (!std::all_of(files.cbegin(), files.cend(), ChecksumsUtils::matches_any(patterns))
        && !std::none_of(files.cbegin(), files.cend(), ChecksumsUtils::matches_any(patterns))) {
        throw Exception(gpg_error(GPG_ERR_INV_ARG),
                        i18n("Create Checksums: input files must be either all checksum files or all files to be checksummed, not a mixture of both."));
    }
    const QMutexLocker locker(&d->mutex);
    d->files = files;
}

void CreateChecksumsController::setAllowAddition(bool allow)
{
    kleo_assert(!d->isRunning());
    const QMutexLocker locker(&d->mutex);
    d->allowAddition = allow;
}

bool CreateChecksumsController::allowAddition() const
{
    const QMutexLocker locker(&d->mutex);
    return d->allowAddition;
}

void CreateChecksumsController::start()
{
    {
        const QMutexLocker locker(&d->mutex);

#ifndef QT_NO_PROGRESSDIALOG
        d->progressDialog = new QProgressDialog(i18n("Initializing..."), i18n("Cancel"), 0, 0);
        applyWindowID(d->progressDialog);
        d->progressDialog->setAttribute(Qt::WA_DeleteOnClose);
        d->progressDialog->setMinimumDuration(1000);
        d->progressDialog->setWindowTitle(i18nc("@title:window", "Create Checksum Progress"));
        connect(d->progressDialog.data(), &QProgressDialog::canceled, this, &CreateChecksumsController::cancel);
#endif // QT_NO_PROGRESSDIALOG

        d->canceled = false;
        d->errors.clear();
        d->created.clear();
    }

    d->start();
}

void CreateChecksumsController::cancel()
{
    qCDebug(KLEOPATRA_LOG);
    const QMutexLocker locker(&d->mutex);
    d->canceled = true;
}

namespace
{

struct Dir {
    QDir dir;
    QString sumFile;
    QStringList inputFiles;
    quint64 totalSize;
    std::shared_ptr<ChecksumDefinition> checksumDefinition;
};

}

static QStringList remove_checksum_files(QStringList l, const std::vector<QRegularExpression> &rxs)
{
    QStringList::iterator end = l.end();
    for (const auto &rx : rxs) {
        end = std::remove_if(l.begin(), end, [rx](const QString &str) {
            return rx.match(str).hasMatch();
        });
    }
    l.erase(end, l.end());
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

static std::vector<Dir> find_dirs_by_sum_files(const QStringList &files,
                                               bool allowAddition,
                                               const std::function<void(int)> &progress,
                                               const std::vector<std::shared_ptr<ChecksumDefinition>> &checksumDefinitions)
{
    const std::vector<QRegularExpression> patterns = ChecksumsUtils::get_patterns(checksumDefinitions);

    std::vector<Dir> dirs;
    dirs.reserve(files.size());

    int i = 0;

    for (const QString &file : files) {
        const QFileInfo fi(file);
        const QDir dir = fi.dir();
        const QStringList entries = remove_checksum_files(dir.entryList(QDir::Files), patterns);

        QStringList inputFiles;
        if (allowAddition) {
            inputFiles = entries;
        } else {
            const std::vector<ChecksumsUtils::File> parsed = ChecksumsUtils::parse_sum_file(fi.absoluteFilePath());
            QStringList oldInputFiles;
            oldInputFiles.reserve(parsed.size());
            std::transform(parsed.cbegin(), parsed.cend(), std::back_inserter(oldInputFiles), std::mem_fn(&ChecksumsUtils::File::name));
            inputFiles = fs_intersect(oldInputFiles, entries);
        }

        const Dir item = {
            dir,
            fi.fileName(),
            inputFiles,
            aggregate_size(dir, inputFiles),
            ChecksumsUtils::filename2definition(fi.fileName(), checksumDefinitions),
        };

        dirs.push_back(item);

        if (progress) {
            progress(++i);
        }
    }
    return dirs;
}

namespace
{
struct less_dir {
    bool operator()(const QDir &lhs, const QDir &rhs) const
    {
        return QString::compare(lhs.absolutePath(), rhs.absolutePath(), ChecksumsUtils::fs_cs) < 0;
    }
};
}

static std::vector<Dir> find_dirs_by_input_files(const QStringList &files,
                                                 const std::shared_ptr<ChecksumDefinition> &checksumDefinition,
                                                 bool allowAddition,
                                                 const std::function<void(int)> &progress,
                                                 const std::vector<std::shared_ptr<ChecksumDefinition>> &checksumDefinitions)
{
    Q_UNUSED(allowAddition)
    if (!checksumDefinition) {
        return std::vector<Dir>();
    }

    const std::vector<QRegularExpression> patterns = ChecksumsUtils::get_patterns(checksumDefinitions);

    std::map<QDir, QStringList, less_dir> dirs2files;

    // Step 1: sort files by the dir they're contained in:

    std::deque<QString> inputs(files.begin(), files.end());

    int i = 0;
    while (!inputs.empty()) {
        const QString file = inputs.front();
        inputs.pop_front();
        const QFileInfo fi(file);
        if (fi.isDir()) {
            QDir dir(file);
            dirs2files[dir] = remove_checksum_files(dir.entryList(QDir::Files), patterns);
            const auto entryList = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
            std::transform(entryList.cbegin(), entryList.cend(), std::inserter(inputs, inputs.begin()), [&dir](const QString &entry) {
                return dir.absoluteFilePath(entry);
            });
        } else {
            dirs2files[fi.dir()].push_back(file);
        }
        if (progress) {
            progress(++i);
        }
    }

    // Step 2: convert into vector<Dir>:

    std::vector<Dir> dirs;
    dirs.reserve(dirs2files.size());

    for (auto it = dirs2files.begin(), end = dirs2files.end(); it != end; ++it) {
        const QStringList inputFiles = remove_checksum_files(it->second, patterns);
        if (inputFiles.empty()) {
            continue;
        }

        const Dir dir = {
            it->first,
            checksumDefinition->outputFileName(),
            inputFiles,
            aggregate_size(it->first, inputFiles),
            checksumDefinition,
        };
        dirs.push_back(dir);

        if (progress) {
            progress(++i);
        }
    }
    return dirs;
}

static QString process(const Dir &dir, bool *fatal)
{
    const QString absFilePath = dir.dir.absoluteFilePath(dir.sumFile);
    QTemporaryFile out;
    QProcess p;
    if (!out.open()) {
        return QStringLiteral("Failed to open Temporary file.");
    }
    p.setWorkingDirectory(dir.dir.absolutePath());
    p.setStandardOutputFile(out.fileName());
    const QString program = dir.checksumDefinition->createCommand();
    dir.checksumDefinition->startCreateCommand(&p, dir.inputFiles);
    p.waitForFinished(-1);
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

    QFileInfo fi(absFilePath);
    if (!(fi.exists() && !QFile::remove(absFilePath)) && QFile::copy(out.fileName(), absFilePath)) {
        return QString();
    }

    return xi18nc("@info", "Failed to overwrite <filename>%1</filename>.", dir.sumFile);
}

namespace
{
static QDebug operator<<(QDebug s, const Dir &dir)
{
    return s << "Dir(" << dir.dir << "->" << dir.sumFile << "<-(" << dir.totalSize << ')' << dir.inputFiles << ")\n";
}
}

void CreateChecksumsController::Private::run()
{
    QMutexLocker locker(&mutex);

    const QStringList files = this->files;
    const std::vector<std::shared_ptr<ChecksumDefinition>> checksumDefinitions = this->checksumDefinitions;
    const std::shared_ptr<ChecksumDefinition> checksumDefinition = this->checksumDefinition;
    const bool allowAddition = this->allowAddition;

    locker.unlock();

    QStringList errors;
    QStringList created;

    if (!checksumDefinition) {
        errors.push_back(i18n("No checksum programs defined."));
        locker.relock();
        this->errors = errors;
        return;
    } else {
        qCDebug(KLEOPATRA_LOG) << "using checksum-definition" << checksumDefinition->id();
    }

    //
    // Step 1: build a list of work to do (no progress):
    //

    const QString scanning = i18n("Scanning directories...");
    Q_EMIT progress(0, 0, scanning);

    const bool haveSumFiles = std::all_of(files.cbegin(), files.cend(), ChecksumsUtils::matches_any(ChecksumsUtils::get_patterns(checksumDefinitions)));
    const auto progressCb = [this, &scanning](int c) {
        Q_EMIT progress(c, 0, scanning);
    };
    const std::vector<Dir> dirs = haveSumFiles ? find_dirs_by_sum_files(files, allowAddition, progressCb, checksumDefinitions)
                                               : find_dirs_by_input_files(files, checksumDefinition, allowAddition, progressCb, checksumDefinitions);

    for (const Dir &dir : dirs) {
        qCDebug(KLEOPATRA_LOG) << dir;
    }

    if (!canceled) {
        Q_EMIT progress(0, 0, i18n("Calculating total size..."));

        const quint64 total = kdtools::accumulate_transform(dirs.cbegin(), dirs.cend(), std::mem_fn(&Dir::totalSize), Q_UINT64_C(0));

        if (!canceled) {
            //
            // Step 2: perform work (with progress reporting):
            //

            // re-scale 'total' to fit into ints (wish QProgressDialog would use quint64...)
            const quint64 factor = total / std::numeric_limits<int>::max() + 1;

            quint64 done = 0;
            for (const Dir &dir : dirs) {
                Q_EMIT progress(done / factor, total / factor, i18n("Checksumming (%2) in %1", dir.checksumDefinition->label(), dir.dir.path()));
                bool fatal = false;
                const QString error = process(dir, &fatal);
                if (!error.isEmpty()) {
                    errors.push_back(error);
                } else {
                    created.push_back(dir.dir.absoluteFilePath(dir.sumFile));
                }
                done += dir.totalSize;
                if (fatal || canceled) {
                    break;
                }
            }
            Q_EMIT progress(done / factor, total / factor, i18n("Done."));
        }
    }

    locker.relock();

    this->errors = errors;
    this->created = created;

    // mutex unlocked by QMutexLocker
}

#include "createchecksumscontroller.moc"
#include "moc_createchecksumscontroller.cpp"
