/* -*- mode: c++; c-basic-offset:4 -*-
    newcertificatewizard/enterdetailspage.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "enterdetailspage_p.h"

#include "advancedsettingsdialog_p.h"

#include "utils/scrollarea.h"
#include "utils/userinfo.h"

#include <settings.h>

#include <Libkleo/Compat>
#include <Libkleo/Dn>
#include <Libkleo/Formatting>
#include <Libkleo/OidMap>
#include <Libkleo/Stl_Util>
#include <Libkleo/Validation>

#include <KLocalizedString>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <QCheckBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMetaProperty>
#include <QPushButton>
#include <QSpacerItem>
#include <QVBoxLayout>
#include <QValidator>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::NewCertificateUi;
using namespace GpgME;

static void set_tab_order(const QList<QWidget *> &wl)
{
    kdtools::for_each_adjacent_pair(wl.begin(), wl.end(), [](QWidget *w1, QWidget *w2) {
        QWidget::setTabOrder(w1, w2);
    });
}

static QString pgpLabel(const QString &attr)
{
    if (attr == QLatin1StringView("NAME")) {
        return i18n("Name");
    }
    if (attr == QLatin1StringView("EMAIL")) {
        return i18n("EMail");
    }
    return QString();
}

static QString attributeLabel(const QString &attr, bool pgp)
{
    if (attr.isEmpty()) {
        return QString();
    }
    const QString label = pgp ? pgpLabel(attr) : Kleo::DN::attributeNameToLabel(attr);
    if (!label.isEmpty())
        if (pgp) {
            return label;
        } else
            return i18nc("Format string for the labels in the \"Your Personal Data\" page", "%1 (%2)", label, attr);
    else {
        return attr;
    }
}

static QString attributeFromKey(QString key)
{
    return key.remove(QLatin1Char('!'));
}

struct EnterDetailsPage::UI {
    QGridLayout *gridLayout = nullptr;
    QLabel *nameLB = nullptr;
    QLineEdit *nameLE = nullptr;
    QLabel *nameRequiredLB = nullptr;
    QLabel *emailLB = nullptr;
    QLineEdit *emailLE = nullptr;
    QLabel *emailRequiredLB = nullptr;
    QCheckBox *withPassCB = nullptr;
    QLineEdit *resultLE = nullptr;
    QLabel *errorLB = nullptr;
    QPushButton *advancedPB = nullptr;

    UI(QWizardPage *parent)
    {
        parent->setTitle(i18nc("@title", "Enter Details"));

        auto mainLayout = new QVBoxLayout{parent};
        const auto margins = mainLayout->contentsMargins();
        mainLayout->setContentsMargins(margins.left(), 0, margins.right(), 0);

        auto scrollArea = new ScrollArea{parent};
        scrollArea->setFocusPolicy(Qt::NoFocus);
        scrollArea->setFrameStyle(QFrame::NoFrame);
        scrollArea->setBackgroundRole(parent->backgroundRole());
        scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scrollArea->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
        auto scrollAreaLayout = qobject_cast<QBoxLayout *>(scrollArea->widget()->layout());
        scrollAreaLayout->setContentsMargins(0, margins.top(), 0, margins.bottom());

        gridLayout = new QGridLayout;
        int row = 0;

        nameLB = new QLabel{i18n("Real name:"), parent};
        nameLE = new QLineEdit{parent};
        nameRequiredLB = new QLabel{i18n("(required)"), parent};
        gridLayout->addWidget(nameLB, row, 0, 1, 1);
        gridLayout->addWidget(nameLE, row, 1, 1, 1);
        gridLayout->addWidget(nameRequiredLB, row, 2, 1, 1);

        row++;
        emailLB = new QLabel{i18n("EMail address:"), parent};
        emailLE = new QLineEdit{parent};
        emailRequiredLB = new QLabel{i18n("(required)"), parent};

        gridLayout->addWidget(emailLB, row, 0, 1, 1);
        gridLayout->addWidget(emailLE, row, 1, 1, 1);
        gridLayout->addWidget(emailRequiredLB, row, 2, 1, 1);

        row++;
        withPassCB = new QCheckBox{i18n("Protect the generated key with a passphrase."), parent};
        withPassCB->setToolTip(
            i18nc("@info:tooltip", "Encrypts the secret key with an unrecoverable passphrase. You will be asked for the passphrase during key generation."));
        gridLayout->addWidget(withPassCB, row, 1, 1, 2);

        scrollAreaLayout->addLayout(gridLayout);

        auto verticalSpacer = new QSpacerItem{20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding};

        scrollAreaLayout->addItem(verticalSpacer);

        resultLE = new QLineEdit{parent};
        resultLE->setFrame(false);
        resultLE->setAlignment(Qt::AlignCenter);
        resultLE->setReadOnly(true);

        scrollAreaLayout->addWidget(resultLE);

        auto horizontalLayout = new QHBoxLayout;
        errorLB = new QLabel{parent};
        QSizePolicy sizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(errorLB->sizePolicy().hasHeightForWidth());
        errorLB->setSizePolicy(sizePolicy);
        QPalette palette;
        QBrush brush(QColor(255, 0, 0, 255));
        brush.setStyle(Qt::SolidPattern);
        palette.setBrush(QPalette::Active, QPalette::WindowText, brush);
        palette.setBrush(QPalette::Inactive, QPalette::WindowText, brush);
        QBrush brush1(QColor(114, 114, 114, 255));
        brush1.setStyle(Qt::SolidPattern);
        palette.setBrush(QPalette::Disabled, QPalette::WindowText, brush1);
        errorLB->setPalette(palette);
        errorLB->setTextFormat(Qt::RichText);

        horizontalLayout->addWidget(errorLB);

        advancedPB = new QPushButton{i18n("Advanced Settings..."), parent};
        advancedPB->setAutoDefault(false);

        horizontalLayout->addWidget(advancedPB);

        scrollAreaLayout->addLayout(horizontalLayout);

        mainLayout->addWidget(scrollArea);
    }
};

EnterDetailsPage::EnterDetailsPage(QWidget *p)
    : WizardPage{p}
    , ui{new UI{this}}
    , dialog{new AdvancedSettingsDialog{this}}
{
    setObjectName(QLatin1StringView("Kleo__NewCertificateUi__EnterDetailsPage"));

    Settings settings;
    if (settings.hideAdvanced()) {
        setSubTitle(i18n("Please enter your personal details below."));
    } else {
        setSubTitle(i18n("Please enter your personal details below. If you want more control over the parameters, click on the Advanced Settings button."));
    }
    ui->advancedPB->setVisible(!settings.hideAdvanced());
    ui->resultLE->setFocusPolicy(Qt::NoFocus);

    // set errorLB to have a fixed height of two lines:
    ui->errorLB->setText(QStringLiteral("2<br>1"));
    ui->errorLB->setFixedHeight(ui->errorLB->minimumSizeHint().height());
    ui->errorLB->clear();

    connect(ui->advancedPB, &QPushButton::clicked, this, &EnterDetailsPage::slotAdvancedSettingsClicked);
    connect(ui->resultLE, &QLineEdit::textChanged, this, &QWizardPage::completeChanged);
    // The email doesn't necessarily show up in ui->resultLE:
    connect(ui->emailLE, &QLineEdit::textChanged, this, &QWizardPage::completeChanged);
    registerDialogPropertiesAsFields();
    registerField(QStringLiteral("dn"), ui->resultLE);
    registerField(QStringLiteral("name"), ui->nameLE);
    registerField(QStringLiteral("email"), ui->emailLE);
    registerField(QStringLiteral("protectedKey"), ui->withPassCB);
    setCommitPage(true);
    setButtonText(QWizard::CommitButton, i18nc("@action", "Create"));

    const auto conf = QGpgME::cryptoConfig();
    if (!conf) {
        qCWarning(KLEOPATRA_LOG) << "Failed to obtain cryptoConfig.";
        return;
    }
    const auto entry = getCryptoConfigEntry(conf, "gpg-agent", "enforce-passphrase-constraints");
    if (entry && entry->boolValue()) {
        qCDebug(KLEOPATRA_LOG) << "Disabling passphrace cb because of agent config.";
        ui->withPassCB->setEnabled(false);
        ui->withPassCB->setChecked(true);
    } else {
        const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("CertificateCreationWizard"));
        ui->withPassCB->setChecked(config.readEntry("WithPassphrase", false));
        ui->withPassCB->setEnabled(!config.isEntryImmutable("WithPassphrase"));
    }
}

EnterDetailsPage::~EnterDetailsPage() = default;

void EnterDetailsPage::initializePage()
{
    updateForm();
    ui->withPassCB->setVisible(false);
}

void EnterDetailsPage::cleanupPage()
{
    saveValues();
}

void EnterDetailsPage::registerDialogPropertiesAsFields()
{
    const QMetaObject *const mo = dialog->metaObject();
    for (unsigned int i = mo->propertyOffset(), end = i + mo->propertyCount(); i != end; ++i) {
        const QMetaProperty mp = mo->property(i);
        if (mp.isValid()) {
            registerField(QLatin1StringView(mp.name()), dialog, mp.name(), SIGNAL(accepted()));
        }
    }
}

void EnterDetailsPage::saveValues()
{
    for (const Line &line : std::as_const(lineList)) {
        savedValues[attributeFromKey(line.attr)] = line.edit->text().trimmed();
    }
}

void EnterDetailsPage::clearForm()
{
    qDeleteAll(dynamicWidgets);
    dynamicWidgets.clear();
    lineList.clear();

    ui->nameLE->hide();
    ui->nameLE->clear();
    ui->nameLB->hide();
    ui->nameRequiredLB->hide();

    ui->emailLE->hide();
    ui->emailLE->clear();
    ui->emailLB->hide();
    ui->emailRequiredLB->hide();
}

static int row_index_of(QWidget *w, QGridLayout *l)
{
    const int idx = l->indexOf(w);
    int r, c, rs, cs;
    l->getItemPosition(idx, &r, &c, &rs, &cs);
    return r;
}

static QLineEdit *
adjust_row(QGridLayout *l, int row, const QString &label, const QString &preset, const std::shared_ptr<QValidator> &validator, bool readonly, bool required)
{
    Q_ASSERT(l);
    Q_ASSERT(row >= 0);
    Q_ASSERT(row < l->rowCount());

    auto lb = qobject_cast<QLabel *>(l->itemAtPosition(row, 0)->widget());
    Q_ASSERT(lb);
    auto le = qobject_cast<QLineEdit *>(l->itemAtPosition(row, 1)->widget());
    Q_ASSERT(le);
    lb->setBuddy(le); // For better accessibility
    auto reqLB = qobject_cast<QLabel *>(l->itemAtPosition(row, 2)->widget());
    Q_ASSERT(reqLB);

    lb->setText(i18nc("interpunctation for labels", "%1:", label));
    le->setText(preset);
    reqLB->setText(required ? i18n("(required)") : i18n("(optional)"));
    if (validator) {
        le->setValidator(validator.get());
    }

    le->setReadOnly(readonly && le->hasAcceptableInput());

    lb->show();
    le->show();
    reqLB->show();

    return le;
}

static int add_row(QGridLayout *l, QList<QWidget *> *wl)
{
    Q_ASSERT(l);
    Q_ASSERT(wl);
    const int row = l->rowCount();
    QWidget *w1, *w2, *w3;
    l->addWidget(w1 = new QLabel(l->parentWidget()), row, 0);
    l->addWidget(w2 = new QLineEdit(l->parentWidget()), row, 1);
    l->addWidget(w3 = new QLabel(l->parentWidget()), row, 2);
    wl->push_back(w1);
    wl->push_back(w2);
    wl->push_back(w3);
    return row;
}

void EnterDetailsPage::updateForm()
{
    clearForm();

    const auto settings = Kleo::Settings{};
    const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("CertificateCreationWizard"));

    QStringList attrOrder = config.readEntry("DNAttributeOrder", QStringList());
    if (attrOrder.empty()) {
        attrOrder << QStringLiteral("CN!") << QStringLiteral("L") << QStringLiteral("OU") << QStringLiteral("O") << QStringLiteral("C")
                  << QStringLiteral("EMAIL!");
    }

    QList<QWidget *> widgets;
    widgets.push_back(ui->nameLE);
    widgets.push_back(ui->emailLE);

    QMap<int, Line> lines;

    for (const QString &rawKey : std::as_const(attrOrder)) {
        const QString key = rawKey.trimmed().toUpper();
        const QString attr = attributeFromKey(key);
        if (attr.isEmpty()) {
            continue;
        }
        const QString preset = savedValues.value(attr, config.readEntry(attr, QString()));
        const bool required = key.endsWith(QLatin1Char('!'));
        const bool readonly = config.isEntryImmutable(attr);
        const QString label = config.readEntry(attr + QLatin1StringView("_label"), attributeLabel(attr, false));
        const QString regex = config.readEntry(attr + QLatin1StringView("_regex"));
        const QString placeholder = config.readEntry(attr + QLatin1StringView{"_placeholder"});

        int row;
        bool known = true;
        std::shared_ptr<QValidator> validator;
        if (attr == QLatin1StringView("EMAIL")) {
            row = row_index_of(ui->emailLE, ui->gridLayout);
            validator = regex.isEmpty() ? Validation::email() : Validation::email(regex);
        } else if (attr == QLatin1StringView("NAME") || attr == QLatin1StringView("CN")) {
            if (attr == QLatin1StringView("NAME")) {
                continue;
            }
            row = row_index_of(ui->nameLE, ui->gridLayout);
        } else {
            known = false;
            row = add_row(ui->gridLayout, &dynamicWidgets);
        }
        if (!validator && !regex.isEmpty()) {
            validator = std::make_shared<QRegularExpressionValidator>(QRegularExpression{regex});
        }

        QLineEdit *le = adjust_row(ui->gridLayout, row, label, preset, validator, readonly, required);
        le->setPlaceholderText(placeholder);

        const Line line = {key, label, regex, le, validator};
        lines[row] = line;

        if (!known) {
            widgets.push_back(le);
        }

        // don't connect twice:
        disconnect(le, &QLineEdit::textChanged, this, &EnterDetailsPage::slotUpdateResultLabel);
        connect(le, &QLineEdit::textChanged, this, &EnterDetailsPage::slotUpdateResultLabel);
    }

    // create lineList in visual order, so requirementsAreMet()
    // complains from top to bottom:
    lineList.reserve(lines.count());
    std::copy(lines.cbegin(), lines.cend(), std::back_inserter(lineList));

    widgets.push_back(ui->withPassCB);
    widgets.push_back(ui->advancedPB);

    if (ui->nameLE->text().isEmpty() && settings.prefillCN()) {
        ui->nameLE->setText(userFullName());
    }
    if (ui->emailLE->text().isEmpty() && settings.prefillEmail()) {
        ui->emailLE->setText(userEmailAddress());
    }

    slotUpdateResultLabel();

    set_tab_order(widgets);
}

QString EnterDetailsPage::cmsDN() const
{
    DN dn;
    for (QList<Line>::const_iterator it = lineList.begin(), end = lineList.end(); it != end; ++it) {
        const QString text = it->edit->text().trimmed();
        if (text.isEmpty()) {
            continue;
        }
        QString attr = attributeFromKey(it->attr);
        if (attr == QLatin1StringView("EMAIL")) {
            continue;
        }
        if (const char *const oid = oidForAttributeName(attr)) {
            attr = QString::fromUtf8(oid);
        }
        dn.append(DN::Attribute(attr, text));
    }
    return dn.dn();
}

QString EnterDetailsPage::pgpUserID() const
{
    return Formatting::prettyNameAndEMail(OpenPGP, QString(), ui->nameLE->text().trimmed(), ui->emailLE->text().trimmed(), QString());
}

static bool has_intermediate_input(const QLineEdit *le)
{
    QString text = le->text();
    int pos = le->cursorPosition();
    const QValidator *const v = le->validator();
    return v && v->validate(text, pos) == QValidator::Intermediate;
}

static bool requirementsAreMet(const QList<EnterDetailsPage::Line> &list, QString &error)
{
    bool allEmpty = true;
    for (const auto &line : list) {
        const QLineEdit *le = line.edit;
        if (!le) {
            continue;
        }
        const QString key = line.attr;
        qCDebug(KLEOPATRA_LOG) << "requirementsAreMet(): checking" << key << "against" << le->text() << ":";
        if (le->text().trimmed().isEmpty()) {
            if (key.endsWith(QLatin1Char('!'))) {
                if (line.regex.isEmpty()) {
                    error = xi18nc("@info", "<interface>%1</interface> is required, but empty.", line.label);
                } else
                    error = xi18nc("@info",
                                   "<interface>%1</interface> is required, but empty.<nl/>"
                                   "Local Admin rule: <icode>%2</icode>",
                                   line.label,
                                   line.regex);
                return false;
            }
        } else if (has_intermediate_input(le)) {
            if (line.regex.isEmpty()) {
                error = xi18nc("@info", "<interface>%1</interface> is incomplete.", line.label);
            } else
                error = xi18nc("@info",
                               "<interface>%1</interface> is incomplete.<nl/>"
                               "Local Admin rule: <icode>%2</icode>",
                               line.label,
                               line.regex);
            return false;
        } else if (!le->hasAcceptableInput()) {
            if (line.regex.isEmpty()) {
                error = xi18nc("@info", "<interface>%1</interface> is invalid.", line.label);
            } else
                error = xi18nc("@info",
                               "<interface>%1</interface> is invalid.<nl/>"
                               "Local Admin rule: <icode>%2</icode>",
                               line.label,
                               line.regex);
            return false;
        } else {
            allEmpty = false;
        }
    }
    // Ensure that at least one value is acceptable
    return !allEmpty;
}

bool EnterDetailsPage::isComplete() const
{
    QString error;
    const bool ok = requirementsAreMet(lineList, error);
    ui->errorLB->setText(error);
    return ok;
}

void EnterDetailsPage::slotAdvancedSettingsClicked()
{
    dialog->exec();
}

void EnterDetailsPage::slotUpdateResultLabel()
{
    ui->resultLE->setText(cmsDN());
}

#include "moc_enterdetailspage_p.cpp"
