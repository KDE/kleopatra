/*  view/formtextinput.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QString>

#include <memory>

class QLabel;
class QLineEdit;
class QValidator;
class QWidget;

namespace Kleo
{
class ErrorLabel;

namespace _detail
{
class FormTextInputBase
{
protected:
    FormTextInputBase();

public:
    virtual ~FormTextInputBase();
    FormTextInputBase(const FormTextInputBase &) = delete;
    FormTextInputBase &operator=(const FormTextInputBase &) = delete;
    FormTextInputBase(FormTextInputBase &&) = delete;
    FormTextInputBase &operator=(FormTextInputBase &&) = delete;

    /**
     * Returns the label associated to the controlled widget. Use it to add
     * the label to a layout, but do not use it to set properties of the label
     * for which this class provides setters.
     */
    QLabel *label() const;

    /**
     * Returns the hint label associated to the controlled widget.
     */
    QLabel *hintLabel() const;

    /**
     * Returns the error label associated to the controlled widget.
     */
    ErrorLabel *errorLabel() const;

    /**
     * Sets \p text as text of the label and \p accessibleName as alternative
     * text for assistive tools. If \p accessibleName is empty, then \p text is
     * used instead. Both texts must be plain text.
     *
     * Note: If input is required, then the label is annotated appropriately.
     */
    void setLabelText(const QString &text, const QString &accessibleName = {});

    /**
     * Returns the text that was set with setLabelText.
     */
    QString labelText() const;

    /**
     * Returns the accessible name that was set with setLabelText (or the text
     * if no accessible name was set).
     */
    QString accessibleName() const;

    /**
     * Sets \p text as hint text for this input field and \p accessibleDescription
     * as alternative text for assistive tools. If \p accessibleDescription is
     * empty, then \p text is used instead.  Both texts must be plain text.
     */
    void setHint(const QString &text, const QString &accessibleDescription = {});

    /**
     * Returns the hint that was set with setHint.
     */
    QString hint() const;

    /**
     * Returns the accessible description that was set with setHint (or the hint
     * if no accessible description was set).
     */
    QString accessibleDescription() const;

    /**
     * Marks this input field as required.
     */
    void setIsRequired(bool required);

    /**
     * Returns \c true, if this field needs to be filled out.
     */
    bool isRequired() const;

    /**
     * Sets the validator to use for validating the input.
     *
     * Note: If you wrap a QLineEdit, then do not set a validator (or an input mask)
     *       on it because this will break the correct displaying of the error message.
     */
    void setValidator(const std::shared_ptr<QValidator> &validator);

    /**
     * Sets \p text as error message to display if a value is required for the
     * input field, but if no value has been entered. If \p text is empty, then
     * a default message will be used. Both texts must be plain text.
     * The optional \p accessibleText is used as alternative text for assistive
     * tools.
     */
    void setValueRequiredErrorMessage(const QString &text, const QString &accessibleText = {});

    /**
     * Sets \p text as error message to display if the entered value is not accepted
     * by the validator. If \p text is empty, then a default message will be used.
     * The optional \p accessibleText is used as alternative text for assistive
     * tools. Both texts must be plain text.
     */
    void setInvalidEntryErrorMessage(const QString &text, const QString &accessibleText = {});

    /**
     * Sets the tool tip of the controlled widget and its associated label.
     */
    void setToolTip(const QString &toolTip);

    /**
     * Enables or disables the controlled widget and its associated label.
     * If the widget is disables, then the error label is hidden. Otherwise,
     * the error label is shown if there is an error.
     */
    void setEnabled(bool enabled);

    /**
     * Returns the currently shown error message for this input field.
     */
    QString currentError() const;

    /**
     * Returns \c true, if the input has a value. This function is used to
     * check required input fields for non-empty user input.
     * Needs to be implemented for concrete widget classes.
     * \sa validate
     */
    virtual bool hasValue() const = 0;

    /**
     * Returns \c true, if the input satisfies the validator.
     * Needs to be implemented for concrete widget classes.
     * \sa validate
     */
    virtual bool hasAcceptableInput() const = 0;

protected:
    /**
     * Connects the slots \ref onTextChanged and \ref onEditingFinished to the
     * corresponding signal of the controlled widget.
     * Needs to be implemented for concrete widget classes.
     */
    virtual void connectWidget() = 0;

    /**
     * Sets the controlled widget and creates the associated labels.
     */
    void setWidget(QWidget *widget);

    /**
     * Returns the controlled widget.
     */
    QWidget *widget() const;

    /**
     * Validates \p text with the validator. Should be used when implementing
     * \ref hasAcceptableInput.
     */
    bool validate(const QString &text, int pos) const;

    /**
     * This slot needs to be connected to a signal of the controlled widget
     * that is emitted when the text changes like \ref QLineEdit::textChanged.
     * \sa connectWidget
     */
    void onTextChanged();

    /**
     * This slot needs to be connected to a signal of the controlled widget
     * that is emitted when the widget loses focus (or some user interaction
     * signals that they want to commit the entered text) like
     * \ref QLineEdit::editingFinished.
     * \sa connectWidget
     */
    void onEditingFinished();

private:
    class Private;
    const std::unique_ptr<Private> d;
};
}

/**
 * FormTextInput is a class for simplifying the management of text input widgets
 * like QLineEdit or QTextEdit with associated label and error message for usage
 * in form-like dialogs.
 *
 * Usage hints:
 * * If you wrap a QLineEdit, then do not set a validator (or an input mask)
 *   on it. Instead set the validator on this class.
 *   If you set a validator on the QLineEdit, then showing the error message
 *   when editing is finished does not work because QLineEdit doesn't emit the
 *   editingFinished() signal if the input is not acceptable.
 */
template<class Widget>
class FormTextInput : public _detail::FormTextInputBase
{
    /**
     * Use \ref create to create a new instance.
     */
    FormTextInput() = default;

public:
    /**
     * Creates a new instance of this class with a new instance of \p Widget.
     */
    static auto create(QWidget *parent)
    {
        std::unique_ptr<FormTextInput> self{new FormTextInput};
        self->setWidget(new Widget{parent});
        return self;
    }

    /**
     * Returns the controlled widget.
     */
    Widget *widget() const
    {
        return static_cast<Widget *>(FormTextInputBase::widget());
    }

    bool hasValue() const override;

    bool hasAcceptableInput() const override;

private:
    void connectWidget() override;
};

template<>
bool FormTextInput<QLineEdit>::hasValue() const;

template<>
bool FormTextInput<QLineEdit>::hasAcceptableInput() const;

template<>
void FormTextInput<QLineEdit>::connectWidget();

}
