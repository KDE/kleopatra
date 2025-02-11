/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "pivcardapplicationadministrationkeyinputdialog.h"

#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Dialogs;

class PIVCardApplicationAdministrationKeyInputDialog::Private
{
    friend class ::Kleo::Dialogs::PIVCardApplicationAdministrationKeyInputDialog;

public:
    explicit Private(PIVCardApplicationAdministrationKeyInputDialog *qq);

    void checkAcceptable();

    PIVCardApplicationAdministrationKeyInputDialog *const q;
    QLabel *mLabel;
    QLineEdit *mHexEncodedAdminKeyEdit;
    QPushButton *mOkButton;
    QByteArray adminKey;
};

PIVCardApplicationAdministrationKeyInputDialog::Private::Private(PIVCardApplicationAdministrationKeyInputDialog *qq)
    : q(qq)
    , mLabel(new QLabel(qq))
    , mHexEncodedAdminKeyEdit(new QLineEdit(qq))
    , mOkButton(nullptr)
{
    auto vBox = new QVBoxLayout(q);

    {
        mLabel->setWordWrap(true);
        vBox->addWidget(mLabel);
    }

    {
        const QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        mHexEncodedAdminKeyEdit->setInputMask(QStringLiteral("HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH:HH;_"));
        mHexEncodedAdminKeyEdit->setFont(fixedFont);
        mHexEncodedAdminKeyEdit->setMinimumWidth(QFontMetrics(fixedFont).horizontalAdvance(QStringLiteral("HH:")) * 24);
        connect(mHexEncodedAdminKeyEdit, &QLineEdit::textChanged, q, [this]() {
            checkAcceptable();
        });

        vBox->addWidget(mHexEncodedAdminKeyEdit);
    }

    auto bbox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, qq);

    mOkButton = bbox->button(QDialogButtonBox::Ok);

    mOkButton->setDefault(true);
    mOkButton->setShortcut(Qt::CTRL | Qt::Key_Return);
    connect(bbox, &QDialogButtonBox::rejected, q, [this]() {
        q->reject();
    });
    connect(bbox, &QDialogButtonBox::accepted, q, [this]() {
        q->accept();
    });

    vBox->addWidget(bbox);

    q->setMinimumWidth(400);

    checkAcceptable();
}

void PIVCardApplicationAdministrationKeyInputDialog::Private::checkAcceptable()
{
    mOkButton->setEnabled(mHexEncodedAdminKeyEdit->hasAcceptableInput());
}

PIVCardApplicationAdministrationKeyInputDialog::PIVCardApplicationAdministrationKeyInputDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
}

void PIVCardApplicationAdministrationKeyInputDialog::setLabelText(const QString &text)
{
    d->mLabel->setText(text);
}

QString PIVCardApplicationAdministrationKeyInputDialog::labelText() const
{
    return d->mLabel->text();
}

QByteArray PIVCardApplicationAdministrationKeyInputDialog::adminKey() const
{
    return QByteArray::fromHex(d->mHexEncodedAdminKeyEdit->text().toUtf8());
}

#include "moc_pivcardapplicationadministrationkeyinputdialog.cpp"
