/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/nameandemailwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "nameandemailwidget.h"

#include "view/errorlabel.h"
#include "view/formtextinput.h"

#include <utils/validation.h>

#include <KLocalizedString>

#include <QLineEdit>
#include <QVBoxLayout>

#include "kleopatra_debug.h"

using namespace Kleo;

namespace
{
QString buildUserId(const QString &name, const QString &email)
{
    if (name.isEmpty()) {
        return email;
    } else if (email.isEmpty()) {
        return name;
    } else {
        return QStringLiteral("%1 <%2>").arg(name, email);
    }
}
}

class NameAndEmailWidget::Private
{
    NameAndEmailWidget *const q;

public:
    struct {
        std::unique_ptr<FormTextInput<QLineEdit>> nameInput;
        std::unique_ptr<FormTextInput<QLineEdit>> emailInput;
    } ui;

    explicit Private(NameAndEmailWidget *qq)
        : q{qq}
    {
        auto mainLayout = new QVBoxLayout{q};

        {
            ui.nameInput = FormTextInput<QLineEdit>::create(q);
            ui.nameInput->setLabelText(i18nc("@label", "Name"));
            ui.nameInput->setValueRequiredErrorMessage(i18n("Enter a name."));
            setNamePattern({});

            mainLayout->addWidget(ui.nameInput->label());
            mainLayout->addWidget(ui.nameInput->hintLabel());
            mainLayout->addWidget(ui.nameInput->errorLabel());
            mainLayout->addWidget(ui.nameInput->widget());
        }
        connect(ui.nameInput->widget(), &QLineEdit::textChanged, q, [this]() {
            Q_EMIT q->userIDChanged();
        });

        {
            ui.emailInput = FormTextInput<QLineEdit>::create(q);
            ui.emailInput->setLabelText(i18nc("@label", "Email address"));
            ui.emailInput->setValueRequiredErrorMessage(i18n("Enter an email address."));
            setEmailPattern({});

            mainLayout->addWidget(ui.emailInput->label());
            mainLayout->addWidget(ui.emailInput->hintLabel());
            mainLayout->addWidget(ui.emailInput->errorLabel());
            mainLayout->addWidget(ui.emailInput->widget());
        }
        connect(ui.emailInput->widget(), &QLineEdit::textChanged, q, [this]() {
            Q_EMIT q->userIDChanged();
        });
    }

    void setNamePattern(const QString &regexp)
    {
        if (regexp.isEmpty()) {
            ui.nameInput->setValidator(Validation::simpleName(Validation::Optional));
            ui.nameInput->setInvalidEntryErrorMessage(
                i18n("The name must not include <, >, and @."),
                i18nc("text for screen readers", "The name must not include less-than sign, greater-than sign, and at sign."));
        } else {
            ui.nameInput->setValidator(Validation::simpleName(regexp, Validation::Optional));
            ui.nameInput->setInvalidEntryErrorMessage(i18n("The name must be in the format required by your organization and "
                                                           "it must not include <, >, and @."),
                                                      i18nc("text for screen readers",
                                                            "The name must be in the format required by your organization and "
                                                            "it must not include less-than sign, greater-than sign, and at sign."));
        }
    }

    void setEmailPattern(const QString &regexp)
    {
        if (regexp.isEmpty()) {
            ui.emailInput->setValidator(Validation::email(Validation::Optional));
            ui.emailInput->setInvalidEntryErrorMessage(i18n("Enter an email address in the correct format, like name@example.com."));
        } else {
            ui.emailInput->setValidator(Validation::email(regexp, Validation::Optional));
            ui.emailInput->setInvalidEntryErrorMessage(i18n("Enter an email address in the correct format required by your organization."));
        }
    }

    QString name() const
    {
        return ui.nameInput->widget()->text().trimmed();
    }

    QString email() const
    {
        return ui.emailInput->widget()->text().trimmed();
    }
};

NameAndEmailWidget::NameAndEmailWidget(QWidget *parent, Qt::WindowFlags f)
    : QWidget{parent, f}
    , d(new Private{this})
{
}

NameAndEmailWidget::~NameAndEmailWidget() = default;

void NameAndEmailWidget::setName(const QString &name)
{
    d->ui.nameInput->widget()->setText(name);
}

QString NameAndEmailWidget::name() const
{
    return d->name();
}

void NameAndEmailWidget::setNameIsRequired(bool required)
{
    d->ui.nameInput->setIsRequired(required);
}

bool NameAndEmailWidget::nameIsRequired() const
{
    return d->ui.nameInput->isRequired();
}

void NameAndEmailWidget::setNameLabel(const QString &label)
{
    if (label.isEmpty()) {
        d->ui.nameInput->setLabelText(i18nc("@label", "Name"));
    } else {
        d->ui.nameInput->setLabelText(label);
    }
}

QString NameAndEmailWidget::nameLabel() const
{
    return d->ui.nameInput->labelText();
}

void NameAndEmailWidget::setNameHint(const QString &hint)
{
    d->ui.nameInput->setHint(hint);
}

QString NameAndEmailWidget::nameHint() const
{
    return d->ui.nameInput->hint();
}

void NameAndEmailWidget::setNamePattern(const QString &pattern)
{
    d->setNamePattern(pattern);
}

QString NameAndEmailWidget::nameError() const
{
    return d->ui.nameInput->currentError();
}

void NameAndEmailWidget::setEmail(const QString &email)
{
    d->ui.emailInput->widget()->setText(email);
}

QString NameAndEmailWidget::email() const
{
    return d->email();
}

void NameAndEmailWidget::setEmailIsRequired(bool required)
{
    d->ui.emailInput->setIsRequired(required);
}

bool NameAndEmailWidget::emailIsRequired() const
{
    return d->ui.emailInput->isRequired();
}

void NameAndEmailWidget::setEmailLabel(const QString &label)
{
    if (label.isEmpty()) {
        d->ui.emailInput->setLabelText(i18nc("@label", "Email address"));
    } else {
        d->ui.emailInput->setLabelText(label);
    }
}

QString NameAndEmailWidget::emailLabel() const
{
    return d->ui.emailInput->labelText();
}

void NameAndEmailWidget::setEmailHint(const QString &hint)
{
    d->ui.emailInput->setHint(hint);
}

QString NameAndEmailWidget::emailHint() const
{
    return d->ui.emailInput->hint();
}

void NameAndEmailWidget::setEmailPattern(const QString &pattern)
{
    d->setEmailPattern(pattern);
}

QString NameAndEmailWidget::emailError() const
{
    return d->ui.emailInput->currentError();
}

QString NameAndEmailWidget::userID() const
{
    return buildUserId(name(), email());
}
