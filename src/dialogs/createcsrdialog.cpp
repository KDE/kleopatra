/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "createcsrdialog.h"

#include <settings.h>

#include <dialogs/animatedexpander.h>
#include <dialogs/nameandemailwidget.h>
#include <utils/keyparameters.h>
#include <utils/scrollarea.h>
#include <utils/userinfo.h>
#include <utils/validation.h>
#include <view/errorlabel.h>
#include <view/formtextinput.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Compat>
#include <Libkleo/Compliance>
#include <Libkleo/DnAttributes>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyUsage>
#include <Libkleo/OidMap>

#include <KConfigGroup>
#include <KDateComboBox>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>
#include <KSharedConfig>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFocusEvent>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

#include <QScrollBar>

#include <QGpgME/CryptoConfig>
#include <QGpgME/DN>
#include <QGpgME/Protocol>

#include <kleopatra_debug.h>
#include <utils/qt6compat.h>

using namespace Kleo;
using namespace Qt::Literals::StringLiterals;

static void useBoldFont(QLabel *label)
{
    QFont font = label->font();
    font.setBold(true);
    label->setFont(font);
}

static QString attributeLabel(const QString &attr)
{
    const QString label = DNAttributes::nameToLabel(attr);
    if (!label.isEmpty()) {
        return label;
    } else {
        return attr;
    }
}

namespace
{
struct AttributeInfo {
    QString name{};
    QString preset{};
    QString label{};
    QString regex{};
    QString hint{};
    bool required = false;
    bool readonly = false;
};
}

static std::vector<AttributeInfo> readAttributeOrder(const KConfigGroup &config)
{
    const auto settings = Kleo::Settings{};
    const auto attributeOrder = config.readEntry("DNAttributeOrder", QStringList{u"L"_s, u"OU"_s, u"O"_s, u"C"_s});

    std::vector<AttributeInfo> attributes;
    attributes.reserve(attributeOrder.size() + 2);
    // CN and EMAIL are always the first two attributes
    auto &cn = attributes.emplace_back(AttributeInfo{.name = u"CN"_s, .preset = settings.prefillCN() ? userFullName() : QString{}, .required = true});
    auto &email =
        attributes.emplace_back(AttributeInfo{.name = u"EMAIL"_s, .preset = settings.prefillEmail() ? userEmailAddress() : QString{}, .required = true});

    for (const QString &rawName : attributeOrder) {
        QString name = rawName.trimmed().toUpper();
        const bool required = name.endsWith(u'!');
        if (required) {
            name.chop(1);
        }
        if (name.isEmpty()) {
            continue;
        }
        if (name == "CN"_L1) {
            cn.required = required;
        } else if (name == "EMAIL"_L1) {
            email.required = required;
        } else {
            attributes.emplace_back(AttributeInfo{.name = name, .required = required});
        }
    }

    for (AttributeInfo &attribute : attributes) {
        attribute.preset = config.readEntry(attribute.name);
        attribute.readonly = config.isEntryImmutable(attribute.name);
        attribute.label = config.readEntry(attribute.name + "_label"_L1, attributeLabel(attribute.name));
        attribute.regex = config.readEntry(attribute.name + "_regex"_L1);
        attribute.hint = config.readEntry(attribute.name + "_hint"_L1);
        if (attribute.hint.isEmpty()) {
            attribute.hint = config.readEntry(attribute.name + "_placeholder"_L1);
        }
    }
    return attributes;
}

static QStringList initCompliantAlgorithms()
{
    QStringList compliantAlgorithms;
    for (const auto &algo : DeVSCompliance::compliantAlgorithms()) {
        // currently only RSA is supported for S/MIME certificates
        if (algo.starts_with("rsa")) {
            compliantAlgorithms.push_back(QString::fromStdString(algo));
        }
    }
    return compliantAlgorithms;
}

namespace
{
struct AlgorithmsAndDefault {
    QStringList algorithms;
    QString defaultAlgorithm;
};
}

static AlgorithmsAndDefault readAlgorithms(const KConfigGroup &config)
{
    static const QStringList compliantAlgorithms{initCompliantAlgorithms()};

    AlgorithmsAndDefault result;

    const auto customRsaKeySizes = config.readEntry("RSAKeySizes", QList<int>{});
    if (!customRsaKeySizes.empty()) {
        for (int keySize : customRsaKeySizes) {
            const QString algorithm = u"rsa"_s + QString::number(std::abs(keySize));
            if (compliantAlgorithms.contains(algorithm)) {
                result.algorithms.push_back(algorithm);
                if (keySize < 0) {
                    result.defaultAlgorithm = algorithm;
                }
            } else {
                qCWarning(KLEOPATRA_LOG) << "Ignoring non-compliant RSA key size" << std::abs(keySize);
            }
        }
        if (result.algorithms.empty()) {
            qCWarning(KLEOPATRA_LOG) << "Using default algorithms";
            result.algorithms = compliantAlgorithms;
        }
    } else {
        result.algorithms = compliantAlgorithms;
    }
    if (result.defaultAlgorithm.isEmpty()) {
        if (const auto pubkeyEntry = QGpgME::cryptoConfig()->entry(u"gpgsm"_s, u"default_pubkey_algo"_s)) {
            // default_pubkey_algo values for gpgsm look like "RSA-3072"
            const QString defaultAlgo = pubkeyEntry->stringValue().toLower().remove(u'-');
            if (result.algorithms.contains(defaultAlgo)) {
                result.defaultAlgorithm = defaultAlgo;
            } else {
                qCWarning(KLEOPATRA_LOG) << "Failed to find gpgsm's default algorithm" << defaultAlgo << "in algorithm selection";
            }
        }
    }

    return result;
}

namespace
{
class MultiLineEdit : public QTextEdit
{
    Q_OBJECT
public:
    explicit MultiLineEdit(QWidget *parent = nullptr);

    QStringList values() const;

    QSize minimumSizeHint() const override;
    QSize sizeHint() const override;

Q_SIGNALS:
    void editingFinished();

protected:
    void focusOutEvent(QFocusEvent *) override;

private:
    bool edited = false;
};

MultiLineEdit::MultiLineEdit(QWidget *parent)
    : QTextEdit{parent}
{
    setAcceptRichText(false);
    setLineWrapMode(QTextEdit::NoWrap);
    setTabChangesFocus(true);

    connect(this, &QTextEdit::textChanged, this, [this]() {
        edited = true;
    });
}

QStringList MultiLineEdit::values() const
{
    const QString currentText = toPlainText();
    const auto lines = QStringView{currentText}.split(u'\n', Qt::SkipEmptyParts);
    QStringList result;
    result.reserve(lines.size());
    for (auto line : lines) {
        auto trimmed = line.trimmed();
        if (!trimmed.empty()) {
            result.append(trimmed.toString());
        }
    }
    return result;
}

void MultiLineEdit::focusOutEvent(QFocusEvent *e)
{
    Qt::FocusReason reason = e->reason();
    if (reason != Qt::PopupFocusReason //
        || !(QApplication::activePopupWidget() && QApplication::activePopupWidget()->parentWidget() == this)) {
        if (edited) {
            Q_EMIT editingFinished();
            edited = false;
        }
    }
    QTextEdit::focusOutEvent(e);
}

QSize MultiLineEdit::minimumSizeHint() const
{
    // the minimum height should be about two lines
    return QSize{QTextEdit::minimumSizeHint().width(), 2 * frameWidth() + 2 * fontMetrics().height()};
}

QSize MultiLineEdit::sizeHint() const
{
    // the default height should be about two lines
    return QSize{QTextEdit::sizeHint().width(), 2 * frameWidth() + 2 * fontMetrics().height()};
}
}

template<>
bool FormTextInput<MultiLineEdit>::hasValue() const
{
    const auto w = widget();
    return w && !w->toPlainText().trimmed().isEmpty();
}

template<>
bool FormTextInput<MultiLineEdit>::hasAcceptableInput() const
{
    const auto w = widget();
    if (!w) {
        return false;
    }
    const QString currentText = w->toPlainText();
    const auto lines = QStringView{currentText}.split(u'\n', Qt::SkipEmptyParts);
    return Kleo::all_of(lines, [this](QStringView line) {
        return validate(line.toString(), line.size());
    });
}

template<>
void FormTextInput<MultiLineEdit>::connectWidget()
{
    const auto w = widget();
    QObject::connect(w, &MultiLineEdit::editingFinished, w, [this]() {
        onEditingFinished();
    });
    QObject::connect(w, &MultiLineEdit::textChanged, w, [this]() {
        onTextChanged();
    });
}

namespace
{
class DomainNameValidator : public QValidator
{
public:
    DomainNameValidator() = default;

    State validate(QString &str, int &pos) const override
    {
        Q_UNUSED(pos)
        QUrl url;
        url.setScheme(u"https"_s);
        url.setHost(str, QUrl::DecodedMode);
        if (url.isValid()) {
            return Acceptable;
        }
        return Intermediate;
    }
};

class URIValidator : public QValidator
{
public:
    URIValidator() = default;

    State validate(QString &str, int &pos) const override
    {
        Q_UNUSED(pos)
        QUrl url;
        url.setUrl(str, QUrl::StrictMode);
        if (url.isValid()) {
            return Acceptable;
        }
        return Intermediate;
    }
};
}

class CreateCSRDialog::Private
{
    friend class ::Kleo::CreateCSRDialog;
    CreateCSRDialog *const q;

    struct UI {
        using FormInputField = FormTextInput<QLineEdit>;
        using FormInputFieldPtr = std::unique_ptr<FormInputField>;
        using FormMultiLineInputField = FormTextInput<MultiLineEdit>;

        struct AdditionalAttributeInput {
            QString name;
            FormInputFieldPtr input;
        };

        QLabel *infoLabel;
        ScrollArea *scrollArea;
        NameAndEmailWidget *nameAndEmail;
        AnimatedExpander *expander;
        QComboBox *keyAlgoCB;
        QCheckBox *signingCheck;
        QCheckBox *encryptionCheck;
        std::vector<AdditionalAttributeInput> additionalAttributes;
        std::unique_ptr<FormMultiLineInputField> emailsField;
        std::unique_ptr<FormMultiLineInputField> domainNamesField;
        std::unique_ptr<FormMultiLineInputField> urisField;
        QDialogButtonBox *buttonBox;

        UI(QWidget *dialog)
        {
            // this regular expression is modeled after gnupg/g10/keygen.c:ask_user_id:
            static const QString domainNameRegExp{u"[^0-9<>][^<>@]{4,}"_s};
            // this regular expression is modeled after gnupg/g10/keygen.c:ask_user_id:
            static const QString uriRegExp{u"[^0-9<>][^<>@]{4,}"_s};

            const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("CertificateCreationWizard"));
            const auto attributes = readAttributeOrder(config);
            Q_ASSERT(attributes.size() >= 2);
            const auto &cn = attributes[0];
            const auto &email = attributes[1];

            auto mainLayout = new QVBoxLayout{dialog};

            infoLabel = new QLabel{dialog};
            infoLabel->setWordWrap(true);
            infoLabel->setText(cn.required || email.required //
                                   ? i18n("Enter a name and an email address to use for the certificate.")
                                   : i18n("Enter a name and/or an email address to use for the certificate."));
            mainLayout->addWidget(infoLabel);

            mainLayout->addWidget(new KSeparator{Qt::Horizontal, dialog});

            scrollArea = new ScrollArea{dialog};
            scrollArea->setFocusPolicy(Qt::NoFocus);
            scrollArea->setFrameStyle(QFrame::NoFrame);
            scrollArea->setBackgroundRole(dialog->backgroundRole());
            scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            scrollArea->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
            auto widget = new QWidget;
            scrollArea->setWidget(widget);
            auto scrollAreaLayout = new QVBoxLayout(widget);
            scrollAreaLayout->setContentsMargins(0, 0, 0, 0);

            nameAndEmail = new NameAndEmailWidget{dialog};
            nameAndEmail->setNameIsRequired(cn.required);
            nameAndEmail->setNameLabel(cn.label);
            nameAndEmail->setNameHint(cn.hint);
            nameAndEmail->setNamePattern(cn.regex);
            nameAndEmail->setName(cn.preset);
            nameAndEmail->setEmailIsRequired(email.required);
            nameAndEmail->setEmailLabel(email.label);
            nameAndEmail->setEmailHint(email.hint);
            nameAndEmail->setEmailPattern(email.regex);
            nameAndEmail->setEmail(email.preset);

            nameAndEmail->layout()->setContentsMargins(0, 0, 0, 0);
            scrollAreaLayout->addWidget(nameAndEmail);

            expander = new AnimatedExpander(i18n("Advanced options"), {}, dialog);
            scrollAreaLayout->addWidget(expander);

            auto advancedLayout = new QVBoxLayout;
            expander->setContentLayout(advancedLayout);

            {
                auto label = new QLabel{i18nc("The algorithm and strength of encryption key", "Key material"), dialog};
                useBoldFont(label);
                keyAlgoCB = new QComboBox(dialog);
                label->setBuddy(keyAlgoCB);
                const auto algos = readAlgorithms(config);
                keyAlgoCB->addItems(algos.algorithms);
                if (!algos.defaultAlgorithm.isEmpty()) {
                    keyAlgoCB->setCurrentText(algos.defaultAlgorithm);
                }

                advancedLayout->addWidget(label);
                advancedLayout->addWidget(keyAlgoCB);
            }

            {
                auto label = new QLabel{i18nc("@label", "Certificate usage"), dialog};
                useBoldFont(label);
                advancedLayout->addWidget(label);

                auto hbox = new QHBoxLayout;
                signingCheck = new QCheckBox{i18nc("@option:check", "Signing"), dialog};
                signingCheck->setChecked(true);
                hbox->addWidget(signingCheck);
                encryptionCheck = new QCheckBox{i18nc("@option:check", "Encryption"), dialog};
                encryptionCheck->setChecked(true);
                hbox->addWidget(encryptionCheck);
                advancedLayout->addLayout(hbox);
            }

            for (const AttributeInfo &attr : std::span{attributes}.subspan(2)) {
                auto inputField = FormInputField::create(dialog);
                inputField->setLabelText(attr.label);
                inputField->setIsRequired(attr.required);
                inputField->setHint(attr.hint);
                if (!attr.regex.isEmpty()) {
                    inputField->setValidator(Validation::regularExpressionValidator(attr.regex, Validation::Optional));
                }
                inputField->widget()->setText(attr.preset);
                inputField->widget()->setReadOnly(attr.readonly && inputField->widget()->hasAcceptableInput());

                advancedLayout->addWidget(inputField->label());
                advancedLayout->addWidget(inputField->hintLabel());
                advancedLayout->addWidget(inputField->widget());
                advancedLayout->addWidget(inputField->errorLabel());

                additionalAttributes.push_back({attr.name, std::move(inputField)});
            }

            emailsField = FormMultiLineInputField::create(dialog);
            emailsField->setLabelText(i18nc("@label:textbox", "Additional email addresses"));
            emailsField->setValidator(Validation::email(Validation::Optional));
            emailsField->setInvalidEntryErrorMessage(i18n("Enter email addresses in the correct format, like name@example.com."));

            advancedLayout->addWidget(emailsField->label());
            advancedLayout->addWidget(emailsField->hintLabel());
            advancedLayout->addWidget(emailsField->widget(), 1);
            advancedLayout->addWidget(emailsField->errorLabel());

            domainNamesField = FormMultiLineInputField::create(dialog);
            domainNamesField->setLabelText(i18nc("@label:textbox", "Domain names"));
            domainNamesField->setValidator(std::make_shared<Validation::TrimmingValidator<Validation::EmptyIsAcceptableValidator<DomainNameValidator>>>());
            domainNamesField->setInvalidEntryErrorMessage(i18n("Enter domain names in the correct format, like www.example.com."));

            advancedLayout->addWidget(domainNamesField->label());
            advancedLayout->addWidget(domainNamesField->hintLabel());
            advancedLayout->addWidget(domainNamesField->widget(), 1);
            advancedLayout->addWidget(domainNamesField->errorLabel());

            urisField = FormMultiLineInputField::create(dialog);
            urisField->setLabelText(i18nc("@label:textbox", "URIs"));
            urisField->setValidator(std::make_shared<Validation::TrimmingValidator<Validation::EmptyIsAcceptableValidator<URIValidator>>>());
            urisField->setInvalidEntryErrorMessage(i18n("Enter URIs in the correct format."));

            advancedLayout->addWidget(urisField->label());
            advancedLayout->addWidget(urisField->hintLabel());
            advancedLayout->addWidget(urisField->widget(), 1);
            advancedLayout->addWidget(urisField->errorLabel());

            scrollAreaLayout->addStretch(1);

            mainLayout->addWidget(scrollArea);

            mainLayout->addWidget(new KSeparator{Qt::Horizontal, dialog});

            buttonBox = new QDialogButtonBox{QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog};

            mainLayout->addWidget(buttonBox);
        }
    } ui;

public:
    explicit Private(CreateCSRDialog *qq)
        : q{qq}
        , ui{qq}
        , technicalParameters{KeyParameters::CMS}
    {
        connect(ui.keyAlgoCB, &QComboBox::currentIndexChanged, q, [this]() {
            updateTechnicalParameters();
        });
        connect(ui.signingCheck, &QCheckBox::toggled, q, [this]() {
            if (!ui.signingCheck->isChecked() && !ui.encryptionCheck->isChecked()) {
                ui.encryptionCheck->setChecked(true);
            } else {
                updateTechnicalParameters();
            }
        });
        connect(ui.encryptionCheck, &QCheckBox::toggled, q, [this]() {
            if (!ui.encryptionCheck->isChecked() && !ui.signingCheck->isChecked()) {
                ui.signingCheck->setChecked(true);
            } else {
                updateTechnicalParameters();
            }
        });
        updateTechnicalParameters();

        const auto settings = Kleo::Settings{};
        ui.expander->setVisible(!settings.hideAdvanced());
        connect(ui.expander, &AnimatedExpander::startExpanding, q, [this]() {
            const auto sh = q->sizeHint();
            const auto margins = q->layout()->contentsMargins();
            q->resize(std::max(sh.width(), ui.expander->contentWidth() + margins.left() + margins.right()), sh.height() + ui.expander->contentHeight());
        });

        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, [this]() {
            checkAccept();
        });
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &QDialog::reject);
    }

private:
    void updateTechnicalParameters()
    {
        technicalParameters = KeyParameters{KeyParameters::CMS};

        technicalParameters.setKeyType(GpgME::Subkey::AlgoRSA);
        const auto algoString = ui.keyAlgoCB->currentText();
        technicalParameters.setKeyLength(algoString.mid(3).toInt());

        KeyUsage usage;
        if (ui.signingCheck->isChecked()) {
            usage.setCanSign(true);
        }
        if (ui.encryptionCheck->isChecked()) {
            usage.setCanEncrypt(true);
        }
        technicalParameters.setKeyUsage(usage);

        // DN, email, etc. are set later
    }

    void setTechnicalParameters(const KeyParameters &parameters)
    {
        int index = -1;
        if (parameters.keyType() == GpgME::Subkey::AlgoRSA) {
            index = ui.keyAlgoCB->findData(u"rsa"_s + QString::number(parameters.keyLength()));
        } else {
            qCWarning(KLEOPATRA_LOG) << __func__ << "Invalid key type:" << parameters.keyType();
        }
        if (index >= 0) {
            ui.keyAlgoCB->setCurrentIndex(index);
        }
    }

    QString dn();

    void checkAccept()
    {
        struct LabelAndError {
            QString label;
            QString error;
        };
        std::vector<LabelAndError> labelsAndErrors;
        if (ui.nameAndEmail->userID().isEmpty() && !ui.nameAndEmail->nameIsRequired() && !ui.nameAndEmail->emailIsRequired()) {
            labelsAndErrors.push_back({{}, i18n("Enter a name or an email address.")});
        }
        if (const QString error = ui.nameAndEmail->nameError(); !error.isEmpty()) {
            labelsAndErrors.push_back({ui.nameAndEmail->nameLabel(), error});
        }
        if (const auto error = ui.nameAndEmail->emailError(); !error.isEmpty()) {
            labelsAndErrors.push_back({ui.nameAndEmail->emailLabel(), error});
        }
        for (const auto &attr : ui.additionalAttributes) {
            if (const QString error = attr.input->currentError(); !error.isEmpty()) {
                labelsAndErrors.push_back({attr.input->labelText(), error});
            }
        }
        if (const QString error = ui.emailsField->currentError(); !error.isEmpty()) {
            labelsAndErrors.push_back({ui.emailsField->labelText(), error});
        }
        if (const QString error = ui.domainNamesField->currentError(); !error.isEmpty()) {
            labelsAndErrors.push_back({ui.domainNamesField->labelText(), error});
        }
        if (const QString error = ui.urisField->currentError(); !error.isEmpty()) {
            labelsAndErrors.push_back({ui.urisField->labelText(), error});
        }

        if (labelsAndErrors.size() > 1) {
            QStringList errors;
            errors.reserve(labelsAndErrors.size());
            for (const auto &[label, error] : labelsAndErrors) {
                errors.push_back(label.isEmpty() ? error : i18nc("@info Error in Label of input field: Message", "Error in %1: %2", label, error));
            }
            KMessageBox::errorList(q, i18nc("@info", "Correct the following errors:"), errors);
        } else if (!labelsAndErrors.empty()) {
            const auto &[label, error] = labelsAndErrors.front();
            const QString message = label.isEmpty()
                ? error
                : xi18nc("@info Error in Label of input field: Message", "Error in <interface>%1</interface>: <message>%2</message>", label, error);
            KMessageBox::error(q, message);
        } else {
            q->accept();
        }
    }

private:
    KeyParameters technicalParameters;
};

QString CreateCSRDialog::Private::dn()
{
    QGpgME::DN dn;
    dn.append(QGpgME::DN::Attribute{u"CN"_s, q->name()});
    for (const auto &attr : ui.additionalAttributes) {
        const QString value = attr.input->widget()->text().trimmed();
        if (!value.isEmpty()) {
            if (const char *const oid = Kleo::oidForAttributeName(attr.name)) {
                dn.append(QGpgME::DN::Attribute{QString::fromUtf8(oid), value});
            } else {
                dn.append(QGpgME::DN::Attribute{attr.name, value});
            }
        }
    }
    return dn.dn();
}

CreateCSRDialog::CreateCSRDialog(QWidget *parent, Qt::WindowFlags f)
    : QDialog{parent, f}
    , d(new Private{this})
{
    setWindowTitle(i18nc("title:window", "Create S/MIME Certificate Signing Request"));

    const auto sh = sizeHint();
    const auto margins = layout()->contentsMargins();
    resize(std::max(sh.width(), d->ui.expander->contentWidth() + margins.left() + margins.right()), sh.height());
}

CreateCSRDialog::~CreateCSRDialog() = default;

void CreateCSRDialog::setName(const QString &name)
{
    d->ui.nameAndEmail->setName(name);
}

QString CreateCSRDialog::name() const
{
    return d->ui.nameAndEmail->name();
}

void CreateCSRDialog::setEmail(const QString &email)
{
    d->ui.nameAndEmail->setEmail(email);
}

QString CreateCSRDialog::email() const
{
    return d->ui.nameAndEmail->email();
}

void Kleo::CreateCSRDialog::setKeyParameters(const Kleo::KeyParameters &parameters)
{
    setName(parameters.name());
    const auto emails = parameters.emails();
    if (!emails.empty()) {
        setEmail(emails.front());
    }
    d->setTechnicalParameters(parameters);
}

KeyParameters CreateCSRDialog::keyParameters() const
{
    // set DN, email, etc. on a copy of the technical parameters
    auto parameters = d->technicalParameters;
    parameters.setDN(d->dn());
    parameters.setEmail(email());
    for (const QString &email : d->ui.emailsField->widget()->values()) {
        parameters.addEmail(email);
    }
    for (const QString &domainName : d->ui.domainNamesField->widget()->values()) {
        parameters.addDomainName(domainName);
    }
    for (const QString &uri : d->ui.urisField->widget()->values()) {
        parameters.addURI(uri);
    }
    return parameters;
}

#include "createcsrdialog.moc"
