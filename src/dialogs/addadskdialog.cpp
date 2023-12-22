/* -*- mode: c++; c-basic-offset:4 -*-

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "addadskdialog.h"

#include "crypto/gui/certificatelineedit.h"
#include "dialogs/certificateselectiondialog.h"
#include "utils/scrollarea.h"

#include <Libkleo/DefaultKeyFilter>
#include <Libkleo/Formatting>
#include <Libkleo/KeyListModel>

#include <KLocalizedString>

#include <KMessageWidget>

#include <QDialogButtonBox>
#include <QGroupBox>
#include <QPushButton>
#include <QScreen>
#include <QVBoxLayout>

#include <memory>

using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace GpgME;

class EncryptCertificateFilter : public DefaultKeyFilter
{
public:
    EncryptCertificateFilter(const Key &key)
        : DefaultKeyFilter()
        , m_key(key)
    {
        setRevoked(DefaultKeyFilter::NotSet);
        setExpired(DefaultKeyFilter::NotSet);
        setCanEncrypt(DefaultKeyFilter::Set);
        setValidIfSMIME(DefaultKeyFilter::NotSet);
    }
    bool matches(const Key &key, MatchContexts ctx) const override
    {
        if (m_key.primaryFingerprint() == key.primaryFingerprint()) {
            return false;
        }
        return DefaultKeyFilter::matches(key, ctx);
    }
    Key m_key;
};

class AddADSKDialog::Private
{
public:
    Private(AddADSKDialog *qq, const Key &key)
        : ui{qq, key}
    {
    }

    struct UI {
        KMessageWidget *warning = nullptr;
        CertificateLineEdit *adsk = nullptr;
        QDialogButtonBox *buttonBox = nullptr;

        UI(QDialog *parent, const Key &key)
        {
            const auto mainLayout = new QVBoxLayout{parent};
            {
                const auto groupBox = new QGroupBox(i18nc("@title:group", "ADSK"), parent);
                const auto layout = new QVBoxLayout(parent);

                const auto &model = AbstractKeyListModel::createFlatKeyListModel(parent);
                model->useKeyCache(true, KeyList::AllKeys);
                auto filter = new EncryptCertificateFilter(key);
                adsk = new CertificateLineEdit(model, KeyUsage::Encrypt, filter, parent);

                layout->addWidget(adsk);
                groupBox->setLayout(layout);
                mainLayout->addWidget(groupBox);

                warning = new KMessageWidget(parent);
                warning->setVisible(false);
                warning->setWordWrap(true);
                warning->setMessageType(KMessageWidget::Warning);
                warning->setCloseButtonVisible(false);

                mainLayout->addWidget(warning);
                mainLayout->addStretch(1);
            }

            buttonBox = new QDialogButtonBox{parent};
            buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);
            buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);

            mainLayout->addWidget(buttonBox);
        }
    } ui;
};

AddADSKDialog::AddADSKDialog(const Key &parent, QWidget *p)
    : QDialog{p}
    , d{new Private{this, parent}}
{
    setWindowTitle(i18nc("@title:window", "Add ADSK"));
    const auto size = sizeHint();
    const auto desk = screen()->size();
    resize(QSize(desk.width() / 3, qMin(size.height(), desk.height() / 2)));

    connect(d->ui.buttonBox, &QDialogButtonBox::accepted, this, &AddADSKDialog::accept);
    connect(d->ui.buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(d->ui.adsk, &CertificateLineEdit::keyChanged, this, [this]() {
        if (d->ui.adsk->key().isNull()) {
            return;
        }
        d->ui.warning->setText(i18n("<b>Warning:</b> Every client supporting this will additionally encrypt to this certificate. This means that every message "
                                    "you receive can also be decrypted by <b>%1</b>.")
                                   .arg(Formatting::prettyNameAndEMail(d->ui.adsk->key()).toHtmlEscaped()));
        d->ui.warning->setVisible(true);
    });
    connect(d->ui.adsk, &CertificateLineEdit::certificateSelectionRequested, this, [this, parent]() {
        CertificateSelectionDialog dlg{this};

        dlg.setOptions(CertificateSelectionDialog::Options( //
            CertificateSelectionDialog::SingleSelection | //
            CertificateSelectionDialog::EncryptOnly | //
            CertificateSelectionDialog::optionsFromProtocol(OpenPGP)));

        dlg.setKeyFilter(std::shared_ptr<EncryptCertificateFilter>(new EncryptCertificateFilter(parent)));
        if (!d->ui.adsk->key().isNull()) {
            const auto key = d->ui.adsk->key();
            const auto name = QString::fromUtf8(key.userID(0).name());
            const auto email = QString::fromUtf8(key.userID(0).email());
            dlg.setStringFilter(!name.isEmpty() ? name : email);
        } else {
            dlg.setStringFilter(d->ui.adsk->text());
        }

        if (dlg.exec()) {
            const std::vector<Key> keys = dlg.selectedCertificates();
            if (keys.size() == 0) {
                return;
            }
            CertificateLineEdit *certWidget = d->ui.adsk;
            for (const Key &key : keys) {
                certWidget->setKey(key);
            }
        }
    });
    connect(d->ui.adsk, &CertificateLineEdit::keyChanged, this, [this]() {
        d->ui.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(!d->ui.adsk->key().isNull());
    });
}

Key AddADSKDialog::adsk() const
{
    return d->ui.adsk->key();
}

AddADSKDialog::~AddADSKDialog() = default;

#include "moc_addadskdialog.cpp"
