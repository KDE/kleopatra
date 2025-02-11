/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "gencardkeydialog.h"

#include "smartcard/algorithminfo.h"

#include "utils/userinfo.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include <KColorScheme>
#include <KEmailAddress>
#include <KLocalizedString>

#include "kleopatra_debug.h"

using namespace Kleo;

class GenCardKeyDialog::Private
{
public:
    Private(GenCardKeyDialog *qq, KeyAttributes requiredAttributes)
        : q(qq)
        , mOkButton(nullptr)
        , mNameEdit(nullptr)
        , mEmailEdit(nullptr)
        , mInvalidEmailLabel(nullptr)
        , mAlgorithmCombo(nullptr)
        , mBackupCheckBox(nullptr)
    {
        auto vBox = new QVBoxLayout(q);
        auto grid = new QGridLayout;

        int row = 0;

        if (requiredAttributes & KeyOwnerName) {
            auto nameLabel = new QLabel(i18nc("@label:textbox", "Name:"));
            mNameEdit = new QLineEdit(userFullName());
            connect(mNameEdit, &QLineEdit::textChanged, q, [this]() {
                checkAcceptable();
            });

            grid->addWidget(nameLabel, row, 0);
            grid->addWidget(mNameEdit, row++, 1);
        }
        if (requiredAttributes & KeyOwnerEmail) {
            auto mailLabel = new QLabel(i18nc("@label:textbox", "EMail:"));
            mEmailEdit = new QLineEdit(userEmailAddress());
            connect(mEmailEdit, &QLineEdit::textChanged, q, [this]() {
                checkAcceptable();
            });
            mInvalidEmailLabel = new QLabel(
                QStringLiteral("<font size='small' color='%1'>%2</font>")
                    .arg(KColorScheme(QPalette::Active, KColorScheme::View).foreground(KColorScheme::NegativeText).color().name(), i18n("Invalid EMail")));

            grid->addWidget(mailLabel, row, 0);
            grid->addWidget(mEmailEdit, row++, 1);
            grid->addWidget(mInvalidEmailLabel, row++, 1);
        }
        if (requiredAttributes & KeyAlgorithm) {
            auto algorithmLabel = new QLabel(i18nc("@label:textbox", "Algorithm:"));
            mAlgorithmCombo = new QComboBox;

            grid->addWidget(algorithmLabel, row, 0);
            grid->addWidget(mAlgorithmCombo, row++, 1);
        }
        if (requiredAttributes & LocalKeyBackup) {
            mBackupCheckBox = new QCheckBox(i18nc("@option:check", "Backup encryption key"));
            mBackupCheckBox->setToolTip(i18nc("@info:tooltip", "Backup the encryption key in a file.") + QStringLiteral("<br/>")
                                        + i18n("You will be asked for a passphrase to protect that file during key generation."));
            mBackupCheckBox->setChecked(true);

            grid->addWidget(mBackupCheckBox, row++, 0, 1, 2);
        }

        vBox->addLayout(grid);

        auto bbox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, qq);

        mOkButton = bbox->button(QDialogButtonBox::Ok);

        mOkButton->setDefault(true);
        mOkButton->setShortcut(Qt::CTRL | Qt::Key_Return);
        connect(bbox, &QDialogButtonBox::rejected, q, [this]() {
            q->reject();
        });
        connect(bbox, &QDialogButtonBox::accepted, q, [this]() {
            accept();
        });

        vBox->addWidget(bbox);

        q->setMinimumWidth(400);

        checkAcceptable();
    }

    void accept()
    {
        if (mNameEdit) {
            params.name = mNameEdit->text();
        }
        if (mEmailEdit) {
            params.email = mEmailEdit->text();
        }
        if (mAlgorithmCombo) {
            params.algorithm = mAlgorithmCombo->currentData().toByteArray().toStdString();
        }
        if (mBackupCheckBox) {
            params.backup = mBackupCheckBox->isChecked();
        }
        q->accept();
    }

    void setSupportedAlgorithms(const std::vector<SmartCard::AlgorithmInfo> &algorithms, const std::string &defaultAlgo)
    {
        if (!mAlgorithmCombo) {
            qCWarning(KLEOPATRA_LOG) << "GenCardKeyDialog::setSupportedAlgorithms() called, but algorithm no required key attribute";
            return;
        }

        mAlgorithmCombo->clear();
        for (const auto &algorithm : algorithms) {
            mAlgorithmCombo->addItem(algorithm.displayName, QByteArray::fromStdString(algorithm.id));
        }
        mAlgorithmCombo->setCurrentIndex(mAlgorithmCombo->findData(QByteArray::fromStdString(defaultAlgo)));
    }

    void checkAcceptable()
    {
        if (!mEmailEdit) {
            // email is not required
            return;
        }
        const QString mail = mEmailEdit->text();
        const bool mailIsValid = !mail.isEmpty() && KEmailAddress::isValidSimpleAddress(mail);
        mInvalidEmailLabel->setVisible(!mail.isEmpty() && !mailIsValid);

        const bool nameIsValid = mNameEdit && !mNameEdit->text().isEmpty();
        mOkButton->setEnabled(mailIsValid || nameIsValid);
    }

    GenCardKeyDialog *const q;
    KeyParams params;
    QPushButton *mOkButton;
    QLineEdit *mNameEdit;
    QLineEdit *mEmailEdit;
    QLabel *mInvalidEmailLabel;
    QComboBox *mAlgorithmCombo;
    QCheckBox *mBackupCheckBox;
};

GenCardKeyDialog::GenCardKeyDialog(KeyAttributes requiredAttributes, QWidget *parent)
    : QDialog(parent)
    , d(new Private(this, requiredAttributes))
{
}

void GenCardKeyDialog::setSupportedAlgorithms(const std::vector<SmartCard::AlgorithmInfo> &algorithms, const std::string &defaultAlgo)
{
    d->setSupportedAlgorithms(algorithms, defaultAlgo);
}

GenCardKeyDialog::KeyParams GenCardKeyDialog::getKeyParams() const
{
    return d->params;
}

#include "moc_gencardkeydialog.cpp"
