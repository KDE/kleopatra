/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/revokekeydialog.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "revokekeydialog.h"

#include "utils/accessibility.h"
#include "view/errorlabel.h"

#include <Libkleo/Formatting>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>

#include <QApplication>
#include <QButtonGroup>
#include <QDialogButtonBox>
#include <QFocusEvent>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QRadioButton>
#include <QRegularExpression>
#include <QTextEdit>
#include <QVBoxLayout>

#if QGPGME_SUPPORTS_KEY_REVOCATION
#include <gpgme++/global.h>
#endif
#include <gpgme++/key.h>

#include <kleopatra_debug.h>

using namespace Kleo;
using namespace GpgME;

namespace
{
class TextEdit : public QTextEdit
{
    Q_OBJECT
public:
    using QTextEdit::QTextEdit;

Q_SIGNALS:
    void editingFinished();

protected:
    void focusOutEvent(QFocusEvent *event) override
    {
        Qt::FocusReason reason = event->reason();
        if (reason != Qt::PopupFocusReason || !(QApplication::activePopupWidget() && QApplication::activePopupWidget()->parentWidget() == this)) {
            Q_EMIT editingFinished();
        }

        QTextEdit::focusOutEvent(event);
    }
};
}

class RevokeKeyDialog::Private
{
    friend class ::Kleo::RevokeKeyDialog;
    RevokeKeyDialog *const q;

    struct {
        QLabel *infoLabel = nullptr;
        QLabel *descriptionLabel = nullptr;
        TextEdit *description = nullptr;
        ErrorLabel *descriptionError = nullptr;
        QDialogButtonBox *buttonBox = nullptr;
    } ui;

    Key key;
    QButtonGroup reasonGroup;
    bool descriptionEditingInProgress = false;
    QString descriptionAccessibleName;

public:
    Private(RevokeKeyDialog *qq)
        : q(qq)
    {
        q->setWindowTitle(i18nc("title:window", "Revoke Key"));

        auto mainLayout = new QVBoxLayout{q};

        ui.infoLabel = new QLabel{q};
        mainLayout->addWidget(ui.infoLabel);

#if QGPGME_SUPPORTS_KEY_REVOCATION
        auto groupBox = new QGroupBox{i18nc("@title:group", "Reason for revocation"), q};

        reasonGroup.addButton(new QRadioButton{i18nc("@option:radio", "No reason specified"), q}, static_cast<int>(RevocationReason::Unspecified));
        reasonGroup.addButton(new QRadioButton{i18nc("@option:radio", "Key has been compromised"), q}, static_cast<int>(RevocationReason::Compromised));
        reasonGroup.addButton(new QRadioButton{i18nc("@option:radio", "Key is superseded"), q}, static_cast<int>(RevocationReason::Superseded));
        reasonGroup.addButton(new QRadioButton{i18nc("@option:radio", "Key is no longer used"), q}, static_cast<int>(RevocationReason::NoLongerUsed));
        reasonGroup.button(static_cast<int>(RevocationReason::Unspecified))->setChecked(true);

        {
            auto boxLayout = new QVBoxLayout{groupBox};
            for (auto radio : reasonGroup.buttons()) {
                boxLayout->addWidget(radio);
            }
        }

        mainLayout->addWidget(groupBox);
#endif

        {
            ui.descriptionLabel = new QLabel{i18nc("@label:textbox", "Description (optional):"), q};
            ui.description = new TextEdit{q};
            ui.description->setAcceptRichText(false);
            // do not accept Tab as input; this is better for accessibility and
            // tabulators are not really that useful in the description
            ui.description->setTabChangesFocus(true);
            ui.descriptionLabel->setBuddy(ui.description);
            ui.descriptionError = new ErrorLabel{q};
            ui.descriptionError->setVisible(false);

            mainLayout->addWidget(ui.descriptionLabel);
            mainLayout->addWidget(ui.description);
            mainLayout->addWidget(ui.descriptionError);
        }

        connect(ui.description, &TextEdit::editingFinished, q, [this]() {
            onDescriptionEditingFinished();
        });
        connect(ui.description, &TextEdit::textChanged, q, [this]() {
            onDescriptionTextChanged();
        });

        ui.buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        auto okButton = ui.buttonBox->button(QDialogButtonBox::Ok);
        okButton->setText(i18nc("@action:button", "Revoke Key"));
        okButton->setIcon(QIcon::fromTheme(QStringLiteral("edit-delete-remove")));

        mainLayout->addWidget(ui.buttonBox);

        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, [this]() {
            checkAccept();
        });
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &QDialog::reject);

        restoreGeometry();
    }

    ~Private()
    {
        saveGeometry();
    }

private:
    void saveGeometry()
    {
        KConfigGroup cfgGroup(KSharedConfig::openStateConfig(), "RevokeKeyDialog");
        cfgGroup.writeEntry("Size", q->size());
        cfgGroup.sync();
    }

    void restoreGeometry(const QSize &defaultSize = {})
    {
        KConfigGroup cfgGroup(KSharedConfig::openStateConfig(), "RevokeKeyDialog");
        const QSize size = cfgGroup.readEntry("Size", defaultSize);
        if (size.isValid()) {
            q->resize(size);
        }
    }

    void checkAccept()
    {
        if (!descriptionHasAcceptableInput()) {
            KMessageBox::error(q, descriptionErrorMessage());
        } else {
            q->accept();
        }
    }

    bool descriptionHasAcceptableInput() const
    {
        return !q->description().contains(QLatin1String{"\n\n"});
    }

    QString descriptionErrorMessage() const
    {
        QString message;

        if (!descriptionHasAcceptableInput()) {
            message = i18n("Error: The description must not contain empty lines.");
        }
        return message;
    }

    void updateDescriptionError()
    {
        const auto currentErrorMessage = ui.descriptionError->text();
        const auto newErrorMessage = descriptionErrorMessage();
        if (newErrorMessage == currentErrorMessage) {
            return;
        }
        if (currentErrorMessage.isEmpty() && descriptionEditingInProgress) {
            // delay showing the error message until editing is finished, so that we
            // do not annoy the user with an error message while they are still
            // entering the recipient;
            // on the other hand, we clear the error message immediately if it does
            // not apply anymore and we update the error message immediately if it
            // changed
            return;
        }
        ui.descriptionError->setVisible(!newErrorMessage.isEmpty());
        ui.descriptionError->setText(newErrorMessage);
        updateAccessibleNameAndDescription();
    }

    void updateAccessibleNameAndDescription()
    {
        // fall back to default accessible name if accessible name wasn't set explicitly
        if (descriptionAccessibleName.isEmpty()) {
            descriptionAccessibleName = getAccessibleName(ui.description);
        }
        const bool errorShown = ui.descriptionError->isVisible();

        // Qt does not support "described-by" relations (like WCAG's "aria-describedby" relationship attribute);
        // emulate this by setting the error message as accessible description of the input field
        const auto description = errorShown ? ui.descriptionError->text() : QString{};
        if (ui.description->accessibleDescription() != description) {
            ui.description->setAccessibleDescription(description);
        }

        // Qt does not support IA2's "invalid entry" state (like WCAG's "aria-invalid" state attribute);
        // screen readers say something like "invalid entry" if this state is set;
        // emulate this by adding "invalid entry" to the accessible name of the input field
        // and its label
        const auto name = errorShown ? descriptionAccessibleName + QLatin1String{", "} + invalidEntryText() //
                                     : descriptionAccessibleName;
        if (ui.descriptionLabel->accessibleName() != name) {
            ui.descriptionLabel->setAccessibleName(name);
        }
        if (ui.description->accessibleName() != name) {
            ui.description->setAccessibleName(name);
        }
    }

    void onDescriptionTextChanged()
    {
        descriptionEditingInProgress = true;
        updateDescriptionError();
    }

    void onDescriptionEditingFinished()
    {
        descriptionEditingInProgress = false;
        updateDescriptionError();
    }
};

RevokeKeyDialog::RevokeKeyDialog(QWidget *parent, Qt::WindowFlags f)
    : QDialog{parent, f}
    , d{new Private{this}}
{
}

RevokeKeyDialog::~RevokeKeyDialog() = default;

void RevokeKeyDialog::setKey(const GpgME::Key &key)
{
    d->key = key;
    d->ui.infoLabel->setText(xi18n("<para>You are about to revoke the following key:<nl/>%1</para>").arg(Formatting::summaryLine(key)));
}

#if QGPGME_SUPPORTS_KEY_REVOCATION
GpgME::RevocationReason RevokeKeyDialog::reason() const
{
    return static_cast<RevocationReason>(d->reasonGroup.checkedId());
}
#endif

QString RevokeKeyDialog::description() const
{
    static const QRegularExpression whitespaceAtEndOfLine{QStringLiteral(R"([ \t\r]+\n)")};
    static const QRegularExpression trailingWhitespace{QStringLiteral(R"(\s*$)")};
    return d->ui.description->toPlainText().remove(whitespaceAtEndOfLine).remove(trailingWhitespace);
}

#include "revokekeydialog.moc"

#include "moc_revokekeydialog.cpp"
