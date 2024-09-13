/* utils/windowsprocessdevice.cpp
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2019 g 10code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifdef WIN32
#include "windowsprocessdevice.h"

#include "kleopatra_debug.h"

#include <Libkleo/GnuPG>

#include <windows.h>

#include <QDir>
#include <QRegularExpression>

/* This is the amount of data GPGME reads at once */
#define PIPEBUF_SIZE 16384

using namespace Kleo;

static void CloseHandleX(HANDLE &h)
{
    if (h && h != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(h)) {
            qCWarning(KLEOPATRA_LOG) << "CloseHandle failed!";
        }
        h = nullptr;
    }
}

class WindowsProcessDevice::Private
{
public:
    ~Private();

    Private(const QString &path, const QStringList &args, const QString &wd)
        : mPath(path)
        , mArgs(args)
        , mWorkingDirectory(wd)
        , mStdInRd(nullptr)
        , mStdInWr(nullptr)
        , mStdOutRd(nullptr)
        , mStdOutWr(nullptr)
        , mStdErrRd(nullptr)
        , mStdErrWr(nullptr)
        , mProc(nullptr)
        , mThread(nullptr)
        , mEnded(false)
    {
    }

    bool start(QIODevice::OpenMode mode);

    qint64 write(const char *data, qint64 size)
    {
        if (size < 0 || (size >> 32)) {
            qCDebug(KLEOPATRA_LOG) << "Invalid write";
            return -1;
        }

        if (!mStdInWr) {
            qCDebug(KLEOPATRA_LOG) << "Write to closed or read only device";
            return -1;
        }

        DWORD dwWritten;
        if (!WriteFile(mStdInWr, data, (DWORD)size, &dwWritten, nullptr)) {
            qCDebug(KLEOPATRA_LOG) << "Failed to write";
            return -1;
        }
        if (dwWritten != size) {
            qCDebug(KLEOPATRA_LOG) << "Failed to write everything";
            return -1;
        }
        return size;
    }

    qint64 read(char *data, qint64 maxSize)
    {
        if (!mStdOutRd) {
            qCDebug(KLEOPATRA_LOG) << "Read of closed or write only device";
            return -1;
        }

        if (!maxSize) {
            return 0;
        }

        DWORD exitCode = 0;
        if (GetExitCodeProcess(mProc, &exitCode)) {
            if (exitCode != STILL_ACTIVE) {
                if (exitCode) {
                    qCDebug(KLEOPATRA_LOG) << "Non zero exit code";
                    mError = readAllStdErr();
                    return -1;
                }
                mEnded = true;
                qCDebug(KLEOPATRA_LOG) << "Process finished with code " << exitCode;
            }
        } else {
            qCDebug(KLEOPATRA_LOG) << "GetExitCodeProcess Failed";
        }

        if (mEnded) {
            DWORD avail = 0;
            if (!PeekNamedPipe(mStdOutRd, nullptr, 0, nullptr, &avail, nullptr)) {
                qCDebug(KLEOPATRA_LOG) << "Failed to peek pipe";
                return -1;
            }
            if (!avail) {
                qCDebug(KLEOPATRA_LOG) << "Process ended and nothing more in pipe";
                return 0;
            }
        }

        DWORD dwRead;
        if (!ReadFile(mStdOutRd, data, (DWORD)maxSize, &dwRead, nullptr)) {
            qCDebug(KLEOPATRA_LOG) << "Failed to read";
            return -1;
        }

        return dwRead;
    }

    QString readAllStdErr()
    {
        QString ret;
        if (!mStdErrRd) {
            qCDebug(KLEOPATRA_LOG) << "Read of closed stderr";
        }
        DWORD dwRead = 0;
        do {
            char buf[4096];
            DWORD avail;
            if (!PeekNamedPipe(mStdErrRd, nullptr, 0, nullptr, &avail, nullptr)) {
                qCDebug(KLEOPATRA_LOG) << "Failed to peek pipe";
                return ret;
            }
            if (!avail) {
                return ret;
            }
            ReadFile(mStdErrRd, buf, 4096, &dwRead, nullptr);
            if (dwRead) {
                QByteArray ba(buf, dwRead);
                ret += QString::fromLocal8Bit(ba);
            }
        } while (dwRead);
        return ret;
    }

    void close()
    {
        if (mProc && mProc != INVALID_HANDLE_VALUE) {
            TerminateProcess(mProc, 0xf291);
            CloseHandleX(mProc);
        }
    }

    QString errorString()
    {
        return mError;
    }

    void closeWriteChannel()
    {
        CloseHandleX(mStdInWr);
    }

private:
    QString mPath;
    QStringList mArgs;
    QString mWorkingDirectory;
    QString mError;
    HANDLE mStdInRd;
    HANDLE mStdInWr;
    HANDLE mStdOutRd;
    HANDLE mStdOutWr;
    HANDLE mStdErrRd;
    HANDLE mStdErrWr;
    HANDLE mProc;
    HANDLE mThread;
    bool mEnded;
};

WindowsProcessDevice::WindowsProcessDevice(const QString &path, const QStringList &args, const QString &wd)
    : d(new Private(path, args, wd))
{
}

bool WindowsProcessDevice::open(QIODevice::OpenMode mode)
{
    bool ret = d->start(mode);
    if (ret) {
        setOpenMode(mode);
    }
    return ret;
}

qint64 WindowsProcessDevice::readData(char *data, qint64 maxSize)
{
    return d->read(data, maxSize);
}

qint64 WindowsProcessDevice::writeData(const char *data, qint64 maxSize)
{
    return d->write(data, maxSize);
}

bool WindowsProcessDevice::isSequential() const
{
    return true;
}

void WindowsProcessDevice::closeWriteChannel()
{
    d->closeWriteChannel();
}

void WindowsProcessDevice::close()
{
    d->close();
    QIODevice::close();
}

QString getLastErrorString()
{
    wchar_t *lpMsgBuf = nullptr;
    DWORD dw = GetLastError();

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL,
                   dw,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (wchar_t *)&lpMsgBuf,
                   0,
                   NULL);

    QString ret = QString::fromWCharArray(lpMsgBuf);

    LocalFree(lpMsgBuf);
    return ret;
}

WindowsProcessDevice::Private::~Private()
{
    if (mProc && mProc != INVALID_HANDLE_VALUE) {
        close();
    }
    CloseHandleX(mThread);
    CloseHandleX(mStdInRd);
    CloseHandleX(mStdInWr);
    CloseHandleX(mStdOutRd);
    CloseHandleX(mStdOutWr);
    CloseHandleX(mStdErrRd);
    CloseHandleX(mStdErrWr);
}

static QString qt_create_commandline(const QString &program, const QStringList &arguments, const QString &nativeArguments)
{
    QString args;
    if (!program.isEmpty()) {
        QString programName = program;
        if (!programName.startsWith(QLatin1Char('\"')) && !programName.endsWith(QLatin1Char('\"')) && programName.contains(QLatin1Char(' ')))
            programName = QLatin1Char('\"') + programName + QLatin1Char('\"');
        programName.replace(QLatin1Char('/'), QLatin1Char('\\'));

        // add the prgram as the first arg ... it works better
        args = programName + QLatin1Char(' ');
    }

    for (int i = 0; i < arguments.size(); ++i) {
        QString tmp = arguments.at(i);
        // Quotes are escaped and their preceding backslashes are doubled.
        tmp.replace(QRegularExpression(QLatin1StringView(R"--((\\*)")--")), QLatin1StringView(R"--(\1\1\")--"));
        if (tmp.isEmpty() || tmp.contains(QLatin1Char(' ')) || tmp.contains(QLatin1Char('\t'))) {
            // The argument must not end with a \ since this would be interpreted
            // as escaping the quote -- rather put the \ behind the quote: e.g.
            // rather use "foo"\ than "foo\"
            int i = tmp.length();
            while (i > 0 && tmp.at(i - 1) == QLatin1Char('\\'))
                --i;
            tmp.insert(i, QLatin1Char('"'));
            tmp.prepend(QLatin1Char('"'));
        }
        args += QLatin1Char(' ') + tmp;
    }

    if (!nativeArguments.isEmpty()) {
        if (!args.isEmpty())
            args += QLatin1Char(' ');
        args += nativeArguments;
    }

    return args;
}

bool WindowsProcessDevice::Private::start(QIODevice::OpenMode mode)
{
    if (mode != QIODevice::ReadOnly //
        && mode != QIODevice::WriteOnly //
        && mode != QIODevice::ReadWrite) {
        qCDebug(KLEOPATRA_LOG) << "Unsupported open mode " << mode;
        return false;
    }

    SECURITY_ATTRIBUTES saAttr;
    ZeroMemory(&saAttr, sizeof(SECURITY_ATTRIBUTES));
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create the pipes
    if (!CreatePipe(&mStdOutRd, &mStdOutWr, &saAttr, PIPEBUF_SIZE) //
        || !CreatePipe(&mStdErrRd, &mStdErrWr, &saAttr, 0) //
        || !CreatePipe(&mStdInRd, &mStdInWr, &saAttr, PIPEBUF_SIZE)) {
        qCDebug(KLEOPATRA_LOG) << "Failed to create pipes";
        mError = getLastErrorString();
        return false;
    }

    // Ensure only the proper handles are inherited
    if (!SetHandleInformation(mStdOutRd, HANDLE_FLAG_INHERIT, 0) //
        || !SetHandleInformation(mStdErrRd, HANDLE_FLAG_INHERIT, 0) //
        || !SetHandleInformation(mStdInWr, HANDLE_FLAG_INHERIT, 0)) {
        qCDebug(KLEOPATRA_LOG) << "Failed to set inherit flag";
        mError = getLastErrorString();
        return false;
    }

    PROCESS_INFORMATION piProcInfo;
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    STARTUPINFO siStartInfo;
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = mStdErrWr;
    siStartInfo.hStdOutput = mStdOutWr;
    siStartInfo.hStdInput = mStdInRd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    const auto args = qt_create_commandline(mPath, mArgs, QString());
    wchar_t *cmdLine = wcsdup(reinterpret_cast<const wchar_t *>(args.utf16()));
    const wchar_t *proc = reinterpret_cast<const wchar_t *>(mPath.utf16());
    const QString nativeWorkingDirectory = QDir::toNativeSeparators(mWorkingDirectory);
    const wchar_t *wd = reinterpret_cast<const wchar_t *>(nativeWorkingDirectory.utf16());

    /* Filter out the handles to inherit only the three handles which we want to
     * inherit. As a Qt Application we have a multitude of open handles which
     * may or may not be inheritable. Testing has shown that this reduced about
     * thirty handles. Open File handles in our child application can also cause the
     * read pipe not to be closed correcly on exit. */
    SIZE_T size;
    bool suc = InitializeProcThreadAttributeList(NULL, 1, 0, &size) || GetLastError() == ERROR_INSUFFICIENT_BUFFER;
    if (!suc) {
        qCDebug(KLEOPATRA_LOG) << "Failed to get Attribute List size";
        mError = getLastErrorString();
        return false;
    }
    LPPROC_THREAD_ATTRIBUTE_LIST attributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, size));
    if (!attributeList) {
        qCDebug(KLEOPATRA_LOG) << "Failed to Allocate Attribute List";
        return false;
    }
    suc = InitializeProcThreadAttributeList(attributeList, 1, 0, &size);
    if (!suc) {
        qCDebug(KLEOPATRA_LOG) << "Failed to Initalize Attribute List";
        mError = getLastErrorString();
        return false;
    }

    HANDLE handles[3];
    handles[0] = mStdOutWr;
    handles[1] = mStdErrWr;
    handles[2] = mStdInRd;
    suc = UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, 3 * sizeof(HANDLE), NULL, NULL);
    if (!suc) {
        qCDebug(KLEOPATRA_LOG) << "Failed to Update Attribute List";
        mError = getLastErrorString();
        return false;
    }
    STARTUPINFOEX info;
    ZeroMemory(&info, sizeof(info));
    info.StartupInfo = siStartInfo;
    info.StartupInfo.cb = sizeof(info); // You have to know this,..
    info.lpAttributeList = attributeList;

    // Now lets start
    qCDebug(KLEOPATRA_LOG) << "Spawning:" << args;
    suc = CreateProcessW(proc,
                         cmdLine, // command line
                         NULL, // process security attributes
                         NULL, // primary thread security attributes
                         TRUE, // handles are inherited
                         CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, // creation flags
                         NULL, // use parent's environment
                         wd, // use parent's current directory
                         &info.StartupInfo, // STARTUPINFO pointer
                         &piProcInfo); // receives PROCESS_INFORMATION
    DeleteProcThreadAttributeList(attributeList);
    HeapFree(GetProcessHeap(), 0, attributeList);
    CloseHandleX(mStdOutWr);
    CloseHandleX(mStdErrWr);
    CloseHandleX(mStdInRd);

    free(cmdLine);
    if (!suc) {
        qCDebug(KLEOPATRA_LOG) << "Failed to create process";
        mError = getLastErrorString();
        return false;
    }

    mProc = piProcInfo.hProcess;
    mThread = piProcInfo.hThread;
    if (mode == QIODevice::WriteOnly) {
        CloseHandleX(mStdOutRd);
    }

    if (mode == QIODevice::ReadOnly) {
        CloseHandleX(mStdInWr);
    }

    return true;
}

QString WindowsProcessDevice::errorString()
{
    return d->errorString();
}

#endif

#include "moc_windowsprocessdevice.cpp"
