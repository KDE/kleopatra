/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/setinitialpindialog.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "setinitialpindialog.h"

#include "ui_setinitialpindialog.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <QIcon>

#include <gpgme++/error.h>

using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace GpgME;

enum State {
    Unknown = 0,
    NotSet,
    AlreadySet,
    Ongoing,
    Ok,
    Failed,
    NumStates,
};

const char *icons[] = {
    // PENDING(marc) use better icons, once available
    "", // Unknown
    "", // NotSet
    "security-medium", // AlreadySet
    "view-refresh", // Ongoing
    "security-high", // Ok
    "security-low", // Failed
};

static_assert(sizeof icons / sizeof(*icons) == NumStates, "");

static void update_widget(State state, bool delay, QLabel *resultLB, QLabel *lb, QPushButton *pb, QLabel *statusLB)
{
    Q_ASSERT(state >= 0);
    Q_ASSERT(state < NumStates);
    const char *icon = icons[state];
    if (icon && *icon) {
        resultLB->setPixmap(QIcon::fromTheme(QLatin1StringView(icon)).pixmap(32));
    } else {
        resultLB->setPixmap(QPixmap());
    }
    lb->setEnabled((state == NotSet || state == Failed) && !delay);
    pb->setEnabled((state == NotSet || state == Failed) && !delay);
    if (state == AlreadySet) {
        statusLB->setText(
            xi18nc("@info", "No NullPin found. <warning>If this PIN was not set by you personally, the card might have been tampered with.</warning>"));
    }
}

static QString format_error(const Error &err)
{
    if (err.isCanceled()) {
        return i18nc("@info", "Canceled setting PIN.");
    }
    if (err)
        return xi18nc("@info", "There was an error setting the PIN: <message>%1</message>.", Formatting::errorAsString(err).toHtmlEscaped());
    else {
        return i18nc("@info", "PIN set successfully.");
    }
}

class SetInitialPinDialog::Private
{
    friend class ::Kleo::Dialogs::SetInitialPinDialog;
    SetInitialPinDialog *const q;

public:
    explicit Private(SetInitialPinDialog *qq)
        : q(qq)
        , nksState(Unknown)
        , sigGState(Unknown)
        , ui(q)
    {
    }

private:
    void slotNksButtonClicked()
    {
        nksState = Ongoing;
        ui.nksStatusLB->clear();
        updateWidgets();
        Q_EMIT q->nksPinRequested();
    }

    void slotSigGButtonClicked()
    {
        sigGState = Ongoing;
        ui.sigGStatusLB->clear();
        updateWidgets();
        Q_EMIT q->sigGPinRequested();
    }

private:
    void updateWidgets()
    {
        update_widget(nksState, false, ui.nksResultIcon, ui.nksLB, ui.nksPB, ui.nksStatusLB);
        update_widget(sigGState, nksState == NotSet || nksState == Failed || nksState == Ongoing, ui.sigGResultIcon, ui.sigGLB, ui.sigGPB, ui.sigGStatusLB);
        ui.closePB()->setEnabled(q->isComplete());
        ui.cancelPB()->setEnabled(!q->isComplete());
    }

private:
    State nksState, sigGState;

    struct UI : public Ui::SetInitialPinDialog {
        explicit UI(Dialogs::SetInitialPinDialog *qq)
            : Ui::SetInitialPinDialog()
        {
            setupUi(qq);

            closePB()->setEnabled(false);

            connect(closePB(), &QAbstractButton::clicked, qq, &QDialog::accept);
        }

        QAbstractButton *closePB() const
        {
            Q_ASSERT(dialogButtonBox);
            return dialogButtonBox->button(QDialogButtonBox::Close);
        }

        QAbstractButton *cancelPB() const
        {
            Q_ASSERT(dialogButtonBox);
            return dialogButtonBox->button(QDialogButtonBox::Cancel);
        }

    } ui;
};

SetInitialPinDialog::SetInitialPinDialog(QWidget *p)
    : QDialog(p)
    , d(new Private(this))
{
}

SetInitialPinDialog::~SetInitialPinDialog()
{
}

void SetInitialPinDialog::setNksPinPresent(bool on)
{
    d->nksState = on ? AlreadySet : NotSet;
    d->updateWidgets();
}

void SetInitialPinDialog::setSigGPinPresent(bool on)
{
    d->sigGState = on ? AlreadySet : NotSet;
    d->updateWidgets();
}

void SetInitialPinDialog::setNksPinSettingResult(const Error &err)
{
    d->ui.nksStatusLB->setText(format_error(err));
    d->nksState = (err.isCanceled() ? NotSet //
                       : err        ? Failed
                                    : Ok);
    d->updateWidgets();
}

void SetInitialPinDialog::setSigGPinSettingResult(const Error &err)
{
    d->ui.sigGStatusLB->setText(format_error(err));
    d->sigGState = (err.isCanceled() ? NotSet //
                        : err        ? Failed
                                     : Ok);
    d->updateWidgets();
}

bool SetInitialPinDialog::isComplete() const
{
    return (d->nksState == Ok || d->nksState == AlreadySet);
}

#include "moc_setinitialpindialog.cpp"
