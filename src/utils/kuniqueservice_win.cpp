/*
    kuniqueservice_win.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "kuniqueservice.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QDir>

#include <KLocalizedString>
#include <KMessageBox>

#include "kleopatra_debug.h"
#include <windows.h>

#define MY_DATA_TYPE 12

class KUniqueService::KUniqueServicePrivate
{
    Q_DECLARE_PUBLIC(KUniqueService)
    Q_DISABLE_COPY(KUniqueServicePrivate)

private:
    KUniqueService *q_ptr;
    HWND mResponder;
    HANDLE mResponderProc;

    const QString getWindowName() const
    {
        return QCoreApplication::applicationName() + QStringLiteral("Responder");
    }

    HWND getForeignResponder() const
    {
        const QString qWndName = getWindowName();
        wchar_t *wndName = (wchar_t *)qWndName.utf16();
        HWND ret = FindWindow(wndName, wndName);
        qCDebug(KLEOPATRA_LOG) << "Responder handle:" << ret;
        return ret;
    }

    void createResponder()
    {
        WNDCLASS windowClass;
        const QString qWndName = getWindowName();
        wchar_t *wndName = (wchar_t *)qWndName.utf16();
        windowClass.style = CS_GLOBALCLASS | CS_DBLCLKS;
        windowClass.lpfnWndProc = windowProc;
        windowClass.hInstance = (HINSTANCE)GetModuleHandle(NULL);
        windowClass.lpszClassName = wndName;
        windowClass.hIcon = nullptr;
        windowClass.hCursor = nullptr;
        windowClass.hbrBackground = nullptr;
        windowClass.lpszMenuName = nullptr;
        windowClass.cbClsExtra = 0;
        windowClass.cbWndExtra = 0;
        RegisterClass(&windowClass);
        mResponder = CreateWindow(wndName, wndName, 0, 0, 0, 10, 10, nullptr, nullptr, (HINSTANCE)GetModuleHandle(NULL), nullptr);
        qCDebug(KLEOPATRA_LOG) << "Created responder: " << qWndName << " with handle: " << mResponder;
    }

    void handleRequest(const COPYDATASTRUCT *cds)
    {
        Q_Q(KUniqueService);
        if (cds->dwData != MY_DATA_TYPE) {
            qCDebug(KLEOPATRA_LOG) << "Responder called with invalid data type:" << cds->dwData;
            return;
        }
        if (mResponderProc) {
            qCDebug(KLEOPATRA_LOG) << "Already serving. Terminating process: " << mResponderProc;
            setExitValue(42);
        }
        const QByteArray serialized(static_cast<const char *>(cds->lpData), cds->cbData);
        QDataStream ds(serialized);
        intptr_t curProc;
        ds >> curProc;
        mResponderProc = reinterpret_cast<HANDLE>(curProc);
        QString workDir;
        ds >> workDir;
        QStringList args;
        ds >> args;
        qCDebug(KLEOPATRA_LOG) << "Process handle: " << mResponderProc << " requests activate with args " << args;
        q->emitActivateRequested(args, workDir);
        return;
    }

    KUniqueServicePrivate(KUniqueService *q)
        : q_ptr(q)
        , mResponder(nullptr)
        , mResponderProc(nullptr)
    {
        HWND responder = getForeignResponder();
        if (!responder) {
            // We are the responder
            createResponder();
            return;
        }
        // We are the client
        QByteArray serialized;
        QDataStream ds(&serialized, QIODevice::WriteOnly);
        DWORD responderId = 0;
        GetWindowThreadProcessId(responder, &responderId);
        if (!responderId) {
            qCDebug(KLEOPATRA_LOG) << "No id of responder window";
            return;
        }

        // To allow the other process to terminate the process
        // needs a handle to us with the required access.
        int err = 0;
        HANDLE responderHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, responderId);
        if (!responderHandle) {
            qCDebug(KLEOPATRA_LOG) << "Open process returned NULL. Err: " << GetLastError();
            err = 1;
        } else if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), responderHandle, &mResponderProc, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            qCDebug(KLEOPATRA_LOG) << "Duplicate Handle failed. Err: " << GetLastError();
            err = 2;
        }
        if (err) {
            KMessageBox::error(nullptr,
                               xi18nc("@info",
                                      "<para><application>Kleopatra</application> seems to be running for you already, but with different privileges.</para>"
                                      "<para>This usually happens if <application>Kleopatra</application> is accidentally run as Administrator.</para>"
                                      "<para>Please right click the tray icon of <application>Kleopatra</application> and select 'quit' to try again.</para>"),
                               xi18nc("@title", "<application>Kleopatra</application> failed to start"));
            exit(err);
        }
        CloseHandle(responderHandle);

        ds << reinterpret_cast<intptr_t>(mResponderProc) << QDir::currentPath() << QCoreApplication::arguments();
        COPYDATASTRUCT cds;
        cds.dwData = MY_DATA_TYPE;
        cds.cbData = serialized.size();
        cds.lpData = serialized.data();

        qCDebug(KLEOPATRA_LOG) << "Sending message to existing Window.";
        SendMessage(responder, WM_COPYDATA, 0, (LPARAM)&cds);
        // Usually we should be terminated while sending the message.
        qCDebug(KLEOPATRA_LOG) << "Send message returned.";
    }

    static KUniqueServicePrivate *instance(KUniqueService *q)
    {
        static KUniqueServicePrivate *self;
        if (self) {
            return self;
        }

        self = new KUniqueServicePrivate(q);
        return self;
    }

    static LRESULT CALLBACK windowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        if (message == WM_COPYDATA) {
            const COPYDATASTRUCT *cds = (COPYDATASTRUCT *)lParam;
            // windowProc must be static so the singleton pattern although
            // it doesn't make much sense in here.
            instance(nullptr)->handleRequest(cds);
            return 0;
        }
        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    ~KUniqueServicePrivate()
    {
        if (mResponder) {
            DestroyWindow(mResponder);
        }
    }

    void setExitValue(int code)
    {
        TerminateProcess(mResponderProc, (unsigned int)code);
        mResponderProc = nullptr;
    }
};

KUniqueService::KUniqueService()
    : d_ptr(KUniqueServicePrivate::instance(this))
{
}

KUniqueService::~KUniqueService()
{
    delete d_ptr;
}

void KUniqueService::setExitValue(int code)
{
    Q_D(KUniqueService);
    d->setExitValue(code);
}
