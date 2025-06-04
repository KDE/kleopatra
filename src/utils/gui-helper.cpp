/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "gui-helper.h"

#include <QDialog>
#include <QDialogButtonBox>
#include <QPointer>
#include <QPushButton>
#include <QWidget>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

using namespace Kleo;

/* This is a Hack to workaround the fact that Foregrounding
   a Window is so restricted that it AllowSetForegroundWindow
   does not always work e.g. when the ForegroundWindow timeout
   has not expired. This Hack is semi official but may stop
   working in future windows versions.

   This is similar to what pinentry-qt does on Windows.
   */
#ifdef Q_OS_WIN
BOOL SetForegroundWindowEx(HWND hWnd)
{
    // Attach foreground window thread to our thread
    const DWORD ForeGroundID = GetWindowThreadProcessId(::GetForegroundWindow(), NULL);
    const DWORD CurrentID = GetCurrentThreadId();
    BOOL retval;

    AttachThreadInput(ForeGroundID, CurrentID, TRUE);
    // Do our stuff here
    HWND hLastActivePopupWnd = GetLastActivePopup(hWnd);
    retval = SetForegroundWindow(hLastActivePopupWnd);

    // Detach the attached thread
    AttachThreadInput(ForeGroundID, CurrentID, FALSE);
    return retval;
} // End SetForegroundWindowEx
#endif

void Kleo::aggressive_raise(QWidget *w, bool stayOnTop)
{
    /* Maybe Qt will become aggressive enough one day that
     * this is enough on windows too*/
    w->raise();
    w->setWindowState(Qt::WindowActive);
    w->activateWindow();
#ifdef Q_OS_WIN
    HWND wid = (HWND)w->effectiveWinId();
    /* In the meantime we do our own attention grabbing */
    if (!SetForegroundWindow(wid) && !SetForegroundWindowEx(wid)) {
        OutputDebugStringA("SetForegroundWindow (ex) failed");
        /* Yet another fallback which will not work on some
         * versions and is not recommended by msdn */
        if (!ShowWindow(wid, SW_SHOWNORMAL)) {
            OutputDebugStringA("ShowWindow failed.");
        }
    }
    /* Even if SetForgeoundWindow / SetForegroundWinowEx don't fail
     * we sometimes are still not in the foreground. So we try yet
     * another hack by using SetWindowPos */
    if (!SetWindowPos(wid, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)) {
        OutputDebugStringA("SetWindowPos failed.");
    }
    /* sometimes we want to stay on top even if the user
     * changes focus because we are _aggressive_ and otherwise
     * Outlook might show the "Help I'm unresponsive so I must have
     * crashed" Popup if the user clicks into Outlook while a dialog
     * from us is active. */
    else if (!stayOnTop) {
        // Without moving back to NOTOPMOST we just stay on top.
        // Even if the user changes focus.
        SetWindowPos(wid, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    }
#else
    Q_UNUSED(stayOnTop)
#endif
}

void Kleo::forceSetTabOrder(QWidget *first, QWidget *second)
{
    if (!first || !second || first == second) {
        return;
    }
    // temporarily change the focus policy of the two widgets to something
    // other than Qt::NoFocus because QWidget::setTabOrder() does nothing
    // if either widget has focus policy Qt::NoFocus
    const auto firstFocusPolicy = first->focusPolicy();
    const auto secondFocusPolicy = second->focusPolicy();
    if (firstFocusPolicy == Qt::NoFocus) {
        first->setFocusPolicy(Qt::StrongFocus);
    }
    if (secondFocusPolicy == Qt::NoFocus) {
        second->setFocusPolicy(Qt::StrongFocus);
    }
    QWidget::setTabOrder(first, second);
    if (first->focusPolicy() != firstFocusPolicy) {
        first->setFocusPolicy(firstFocusPolicy);
    }
    if (second->focusPolicy() != secondFocusPolicy) {
        second->setFocusPolicy(secondFocusPolicy);
    }
}

template<typename UnaryPredicate>
bool focusFirstButtonIf(const std::vector<QAbstractButton *> &buttons, UnaryPredicate p)
{
    auto it = std::find_if(std::begin(buttons), std::end(buttons), p);
    if (it != std::end(buttons)) {
        (*it)->setFocus();
        return true;
    }
    return false;
}

bool Kleo::focusFirstCheckedButton(const std::vector<QAbstractButton *> &buttons)
{
    return focusFirstButtonIf(buttons, [](auto btn) {
        return btn && btn->isEnabled() && btn->isChecked();
    });
}

bool Kleo::focusFirstEnabledButton(const std::vector<QAbstractButton *> &buttons)
{
    return focusFirstButtonIf(buttons, [](auto btn) {
        return btn && btn->isEnabled();
    });
}

void Kleo::unsetDefaultButtons(const QDialogButtonBox *buttonBox)
{
    if (!buttonBox) {
        return;
    }
    const auto buttons = buttonBox->buttons();
    for (auto button : buttons) {
        if (auto pushButton = qobject_cast<QPushButton *>(button)) {
            pushButton->setDefault(false);
        }
    }
}

void Kleo::unsetAutoDefaultButtons(const QDialog *dialog)
{
    if (!dialog) {
        return;
    }
    const auto pushButtons = dialog->findChildren<QPushButton *>();
    for (auto pushButton : pushButtons) {
        pushButton->setAutoDefault(false);
    }
}

BulkStateChanger::BulkStateChanger() = default;

void BulkStateChanger::addWidget(QWidget *widget)
{
    if (widget) {
        mWidgets.push_back(widget);
    }
}

void BulkStateChanger::setVisible(bool visible)
{
    for (auto &w : mWidgets) {
        if (w) {
            w->setVisible(visible);
        }
    }
}
