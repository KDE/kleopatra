/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "adduseriddialog.h"

#include "utils/accessibility.h"
#include "view/htmllabel.h"

#include <Libkleo/NameAndEmailWidget>

#include <KAdjustingScrollArea>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>
#include <KSharedConfig>

#include <QDialogButtonBox>
#include <QLabel>
#include <QVBoxLayout>

#include "kleopatra_debug.h"

using namespace Kleo;

class AddUserIDDialog::Private
{
    friend class ::Kleo::AddUserIDDialog;
    AddUserIDDialog *const q;

    struct {
        KAdjustingScrollArea *scrollArea;
        NameAndEmailWidget *nameAndEmail;
        HtmlLabel *resultLabel;
        QDialogButtonBox *buttonBox;
    } ui;

    LabelHelper labelHelper;

public:
    explicit Private(AddUserIDDialog *qq)
        : q{qq}
    {
        q->setWindowTitle(i18nc("title:window", "Add User ID"));

        const KConfigGroup config{KSharedConfig::openConfig(), QLatin1StringView("CertificateCreationWizard")};
        const auto attrOrder = config.readEntry("OpenPGPAttributeOrder", QStringList{});
        const auto nameIsRequired = attrOrder.contains(QLatin1StringView{"NAME!"}, Qt::CaseInsensitive);
        const auto emailIsRequired = attrOrder.contains(QLatin1StringView{"EMAIL!"}, Qt::CaseInsensitive);

        auto mainLayout = new QVBoxLayout{q};

        {
            const auto infoText = nameIsRequired || emailIsRequired //
                ? i18n("Enter a name and an email address to use for the user ID.")
                : i18n("Enter a name and/or an email address to use for the user ID.");
            auto label = new QLabel{infoText, q};
            label->setWordWrap(true);
            mainLayout->addWidget(label);
        }

        mainLayout->addWidget(new KSeparator{Qt::Horizontal, q});

        ui.scrollArea = new KAdjustingScrollArea{q};
        ui.scrollArea->setFocusPolicy(Qt::NoFocus);
        ui.scrollArea->setFrameStyle(QFrame::NoFrame);
        ui.scrollArea->setBackgroundRole(q->backgroundRole());
        ui.scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        ui.scrollArea->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
        auto widget = new QWidget;
        ui.scrollArea->setWidget(widget);
        auto scrollAreaLayout = new QVBoxLayout(widget);
        scrollAreaLayout->setContentsMargins(0, 0, 0, 0);

        ui.nameAndEmail = new NameAndEmailWidget{q};
        ui.nameAndEmail->layout()->setContentsMargins(0, 0, 0, 0);
        ui.nameAndEmail->setNameIsRequired(nameIsRequired);
        ui.nameAndEmail->setNameLabel(config.readEntry("NAME_label"));
        ui.nameAndEmail->setNameHint(config.readEntry("NAME_hint", config.readEntry("NAME_placeholder")));
        ui.nameAndEmail->setNamePattern(config.readEntry("NAME_regex"));
        ui.nameAndEmail->setEmailIsRequired(emailIsRequired);
        ui.nameAndEmail->setEmailLabel(config.readEntry("EMAIL_label"));
        ui.nameAndEmail->setEmailHint(config.readEntry("EMAIL_hint", config.readEntry("EMAIL_placeholder")));
        ui.nameAndEmail->setEmailPattern(config.readEntry("EMAIL_regex"));
        scrollAreaLayout->addWidget(ui.nameAndEmail);

        scrollAreaLayout->addWidget(new KSeparator{Qt::Horizontal, q});

        {
            ui.resultLabel = new HtmlLabel{q};
            ui.resultLabel->setWordWrap(true);
            ui.resultLabel->setFocusPolicy(Qt::ClickFocus);
            labelHelper.addLabel(ui.resultLabel);
            scrollAreaLayout->addWidget(ui.resultLabel);
        }

        scrollAreaLayout->addStretch(1);

        mainLayout->addWidget(ui.scrollArea);

        mainLayout->addWidget(new KSeparator{Qt::Horizontal, q});

        ui.buttonBox = new QDialogButtonBox{QDialogButtonBox::Ok | QDialogButtonBox::Cancel, q};

        mainLayout->addWidget(ui.buttonBox);

        connect(ui.nameAndEmail, &NameAndEmailWidget::userIDChanged, q, [this]() {
            updateResultLabel();
        });
        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, [this]() {
            checkAccept();
        });
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &QDialog::reject);

        updateResultLabel();
    }

private:
    void checkAccept()
    {
        QStringList errors;
        if (ui.nameAndEmail->userID().isEmpty() && !ui.nameAndEmail->nameIsRequired() && !ui.nameAndEmail->emailIsRequired()) {
            errors.push_back(i18n("Enter a name or an email address."));
        }
        const auto nameError = ui.nameAndEmail->nameError();
        if (!nameError.isEmpty()) {
            errors.push_back(nameError);
        }
        const auto emailError = ui.nameAndEmail->emailError();
        if (!emailError.isEmpty()) {
            errors.push_back(emailError);
        }
        if (errors.size() > 1) {
            KMessageBox::errorList(q, i18n("There is a problem."), errors);
        } else if (!errors.empty()) {
            KMessageBox::error(q, errors.first());
        } else {
            q->accept();
        }
    }

    void updateResultLabel()
    {
        ui.resultLabel->setHtml(i18nc("@info",
                                      "<div>This is how the new user ID will be stored in the certificate:</div>"
                                      "<center><strong>%1</strong></center>",
                                      ui.nameAndEmail->userID().toHtmlEscaped()));
    }
};

AddUserIDDialog::AddUserIDDialog(QWidget *parent, Qt::WindowFlags f)
    : QDialog{parent, f}
    , d(new Private{this})
{
}

AddUserIDDialog::~AddUserIDDialog() = default;

void AddUserIDDialog::setName(const QString &name)
{
    d->ui.nameAndEmail->setName(name);
}

QString AddUserIDDialog::name() const
{
    return d->ui.nameAndEmail->name();
}

void AddUserIDDialog::setEmail(const QString &email)
{
    d->ui.nameAndEmail->setEmail(email);
}

QString AddUserIDDialog::email() const
{
    return d->ui.nameAndEmail->email();
}

QString AddUserIDDialog::userID() const
{
    return d->ui.nameAndEmail->userID();
}

#include "moc_adduseriddialog.cpp"
