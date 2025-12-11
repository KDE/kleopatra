/*  view/formtextinput.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "formtextinput.h"

#include "errorlabel.h"
#include "utils/accessibility.h"

#include <KLocalizedString>

#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QValidator>

#include "kleopatra_debug.h"

namespace
{
auto defaultValueRequiredErrorMessage()
{
    return i18nc("@info Used as error message for a required text input", "Enter a value.");
}

auto defaultInvalidEntryErrorMessage()
{
    return i18nc("@info Used as generic error message for a text input", "Enter a value in the correct format.");
}
}

namespace Kleo::_detail
{

class FormTextInputBase::Private
{
    FormTextInputBase *q;

public:
    enum Error {
        EntryOK,
        EntryMissing, // a required entry is missing
        InvalidEntry // the validator doesn't accept the entry
    };

    Private(FormTextInputBase *q)
        : q{q}
        , mValueRequiredErrorMessage{defaultValueRequiredErrorMessage()}
        , mInvalidEntryErrorMessage{defaultInvalidEntryErrorMessage()}
    {
    }

    QString annotatedIfRequired(const QString &text) const;
    void updateLabel();
    void setLabelText(const QString &text, const QString &accessibleName);
    void setHint(const QString &text, const QString &accessibleDescription);
    QString errorMessage(Error error) const;
    QString accessibleErrorMessage(Error error) const;
    void updateError();
    QString accessibleDescription() const;
    void updateAccessibleNameAndDescription();

    QPointer<QLabel> mLabel;
    QPointer<QLabel> mHintLabel;
    QPointer<QWidget> mWidget;
    QPointer<ErrorLabel> mErrorLabel;
    std::shared_ptr<QValidator> mValidator;
    QString mLabelText;
    QString mAccessibleName;
    QString mValueRequiredErrorMessage;
    QString mAccessibleValueRequiredErrorMessage;
    QString mInvalidEntryErrorMessage;
    QString mAccessibleInvalidEntryErrorMessage;
    Error mError = EntryOK;
    bool mRequired = false;
    bool mEditingInProgress = false;
};

QString FormTextInputBase::Private::annotatedIfRequired(const QString &text) const
{
    return mRequired ? i18nc("@label label text (required)", "%1 (required)", text) //
                     : text;
}

void FormTextInputBase::Private::updateLabel()
{
    if (mLabel) {
        mLabel->setText(annotatedIfRequired(mLabelText));
    }
}

void FormTextInputBase::Private::setLabelText(const QString &text, const QString &accessibleName)
{
    mLabelText = text;
    mAccessibleName = accessibleName.isEmpty() ? text : accessibleName;
    updateLabel();
    updateAccessibleNameAndDescription();
}

void FormTextInputBase::Private::setHint(const QString &text, const QString &accessibleDescription)
{
    if (!mHintLabel) {
        return;
    }
    mHintLabel->setVisible(!text.isEmpty());
    mHintLabel->setText(text);
    mHintLabel->setAccessibleName(accessibleDescription.isEmpty() ? text : accessibleDescription);
    updateAccessibleNameAndDescription();
}

namespace
{
QString decoratedError(const QString &text)
{
    return text.isEmpty() ? QString() : i18nc("@info", "Error: %1", text);
}
}

QString FormTextInputBase::Private::errorMessage(Error error) const
{
    switch (error) {
    case EntryOK:
        return {};
    case EntryMissing:
        return mValueRequiredErrorMessage;
    case InvalidEntry:
        return mInvalidEntryErrorMessage;
    }
    return {};
}

QString FormTextInputBase::Private::accessibleErrorMessage(Error error) const
{
    switch (error) {
    case EntryOK:
        return {};
    case EntryMissing:
        return mAccessibleValueRequiredErrorMessage;
    case InvalidEntry:
        return mAccessibleInvalidEntryErrorMessage;
    }
    return {};
}

void FormTextInputBase::Private::updateError()
{
    if (!mErrorLabel) {
        return;
    }

    if (mRequired && !q->hasValue()) {
        mError = EntryMissing;
    } else if (!q->hasAcceptableInput()) {
        mError = InvalidEntry;
    } else {
        mError = EntryOK;
    }

    const auto currentErrorMessage = mErrorLabel->text();
    const auto newErrorMessage = decoratedError(errorMessage(mError));
    if (newErrorMessage == currentErrorMessage) {
        return;
    }
    if (currentErrorMessage.isEmpty() && mEditingInProgress) {
        // delay showing the error message until editing is finished, so that we
        // do not annoy the user with an error message while they are still
        // entering the recipient;
        // on the other hand, we clear the error message immediately if it does
        // not apply anymore and we update the error message immediately if it
        // changed
        return;
    }
    mErrorLabel->setVisible(!newErrorMessage.isEmpty());
    mErrorLabel->setText(newErrorMessage);
    mErrorLabel->setAccessibleName(decoratedError(accessibleErrorMessage(mError)));
    updateAccessibleNameAndDescription();
}

QString FormTextInputBase::Private::accessibleDescription() const
{
    QString description;
    if (mHintLabel) {
        // get the explicitly set accessible hint text
        description = mHintLabel->accessibleName();
    }
    if (description.isEmpty()) {
        // fall back to the default accessible description of the input widget
        description = getAccessibleDescription(mWidget);
    }
    return description;
}

void FormTextInputBase::Private::updateAccessibleNameAndDescription()
{
    // fall back to default accessible name if accessible name wasn't set explicitly
    if (mAccessibleName.isEmpty()) {
        mAccessibleName = getAccessibleName(mWidget);
    }
    const bool errorShown = mErrorLabel && mErrorLabel->isVisible();

    // Qt does not support "described-by" relations (like WCAG's "aria-describedby" relationship attribute);
    // emulate this by setting the hint text and, if the error is shown, the error message as accessible
    // description of the input field
    const auto description = errorShown ? accessibleDescription() + QLatin1String{" "} + mErrorLabel->accessibleName() //
                                        : accessibleDescription();
    if (mWidget && mWidget->accessibleDescription() != description) {
        mWidget->setAccessibleDescription(description);
    }

    // Qt does not support IA2's "invalid entry" state (like WCAG's "aria-invalid" state attribute);
    // screen readers say something like "invalid entry" if this state is set;
    // emulate this by adding "invalid entry" to the accessible name of the input field
    // and its label
    QString name = annotatedIfRequired(mAccessibleName);
    if (errorShown) {
        name += QLatin1String{", "} + invalidEntryText();
    };
    if (mLabel && mLabel->accessibleName() != name) {
        mLabel->setAccessibleName(name);
    }
    if (mWidget && mWidget->accessibleName() != name) {
        mWidget->setAccessibleName(name);
    }
}

FormTextInputBase::FormTextInputBase()
    : d{new Private{this}}
{
}

FormTextInputBase::~FormTextInputBase() = default;

QWidget *FormTextInputBase::widget() const
{
    return d->mWidget;
}

QLabel *FormTextInputBase::label() const
{
    return d->mLabel;
}

QLabel *FormTextInputBase::hintLabel() const
{
    return d->mHintLabel;
}

ErrorLabel *FormTextInputBase::errorLabel() const
{
    return d->mErrorLabel;
}

void FormTextInputBase::setLabelText(const QString &text, const QString &accessibleName)
{
    d->setLabelText(text, accessibleName);
}

QString FormTextInputBase::labelText() const
{
    return d->mLabelText;
}

QString FormTextInputBase::accessibleName() const
{
    return d->mAccessibleName;
}

void FormTextInputBase::setHint(const QString &text, const QString &accessibleDescription)
{
    d->setHint(text, accessibleDescription);
}

QString FormTextInputBase::hint() const
{
    return d->mHintLabel ? d->mHintLabel->text() : QString{};
}

QString FormTextInputBase::accessibleDescription() const
{
    return d->mHintLabel ? d->mHintLabel->accessibleName() : QString{};
}

void FormTextInputBase::setIsRequired(bool required)
{
    d->mRequired = required;
    d->updateLabel();
    d->updateAccessibleNameAndDescription();
}

bool FormTextInputBase::isRequired() const
{
    return d->mRequired;
}

void FormTextInputBase::setValidator(const std::shared_ptr<QValidator> &validator)
{
    Q_ASSERT(!validator || !validator->parent());

    d->mValidator = validator;
}

void FormTextInputBase::setValueRequiredErrorMessage(const QString &text, const QString &accessibleText)
{
    if (text.isEmpty()) {
        d->mValueRequiredErrorMessage = defaultValueRequiredErrorMessage();
    } else {
        d->mValueRequiredErrorMessage = text;
    }
    if (accessibleText.isEmpty()) {
        d->mAccessibleValueRequiredErrorMessage = d->mValueRequiredErrorMessage;
    } else {
        d->mAccessibleValueRequiredErrorMessage = accessibleText;
    }
}

void FormTextInputBase::setInvalidEntryErrorMessage(const QString &text, const QString &accessibleText)
{
    if (text.isEmpty()) {
        d->mInvalidEntryErrorMessage = defaultInvalidEntryErrorMessage();
    } else {
        d->mInvalidEntryErrorMessage = text;
    }
    if (accessibleText.isEmpty()) {
        d->mAccessibleInvalidEntryErrorMessage = d->mInvalidEntryErrorMessage;
    } else {
        d->mAccessibleInvalidEntryErrorMessage = accessibleText;
    }
}

void FormTextInputBase::setToolTip(const QString &toolTip)
{
    if (d->mLabel) {
        d->mLabel->setToolTip(toolTip);
    }
    if (d->mWidget) {
        d->mWidget->setToolTip(toolTip);
    }
}

void FormTextInputBase::setWidget(QWidget *widget)
{
    auto parent = widget ? widget->parentWidget() : nullptr;
    d->mWidget = widget;
    d->mLabel = new QLabel{parent};
    d->mLabel->setTextFormat(Qt::PlainText);
    d->mLabel->setWordWrap(true);
    QFont font = d->mLabel->font();
    font.setBold(true);
    d->mLabel->setFont(font);
    d->mLabel->setBuddy(d->mWidget);
    d->mHintLabel = new QLabel{parent};
    d->mHintLabel->setWordWrap(true);
    d->mHintLabel->setTextFormat(Qt::PlainText);
    // set widget as buddy of hint label, so that the label isn't considered unrelated
    d->mHintLabel->setBuddy(d->mWidget);
    d->mHintLabel->setVisible(false);
    d->mErrorLabel = new ErrorLabel{parent};
    d->mErrorLabel->setWordWrap(true);
    d->mErrorLabel->setTextFormat(Qt::PlainText);
    // set widget as buddy of error label, so that the label isn't considered unrelated
    d->mErrorLabel->setBuddy(d->mWidget);
    d->mErrorLabel->setVisible(false);
    connectWidget();
}

void FormTextInputBase::setEnabled(bool enabled)
{
    if (d->mLabel) {
        d->mLabel->setEnabled(enabled);
    }
    if (d->mWidget) {
        d->mWidget->setEnabled(enabled);
    }
    if (d->mErrorLabel) {
        d->mErrorLabel->setVisible(enabled && !d->mErrorLabel->text().isEmpty());
    }
}

QString FormTextInputBase::currentError() const
{
    if (d->mError) {
        return d->errorMessage(d->mError);
    }
    return {};
}

bool FormTextInputBase::validate(const QString &text, int pos) const
{
    QString textCopy = text;
    if (d->mValidator && d->mValidator->validate(textCopy, pos) != QValidator::Acceptable) {
        return false;
    }
    return true;
}

void FormTextInputBase::onTextChanged()
{
    d->mEditingInProgress = true;
    d->updateError();
}

void FormTextInputBase::onEditingFinished()
{
    d->mEditingInProgress = false;
    d->updateError();
}

}

template<>
bool Kleo::FormTextInput<QLineEdit>::hasValue() const
{
    const auto w = widget();
    return w && !w->text().trimmed().isEmpty();
}

template<>
bool Kleo::FormTextInput<QLineEdit>::hasAcceptableInput() const
{
    const auto w = widget();
    return w && validate(w->text(), w->cursorPosition());
}

template<>
void Kleo::FormTextInput<QLineEdit>::connectWidget()
{
    const auto w = widget();
    QObject::connect(w, &QLineEdit::editingFinished, w, [this]() {
        onEditingFinished();
    });
    QObject::connect(w, &QLineEdit::textChanged, w, [this]() {
        onTextChanged();
    });
}
