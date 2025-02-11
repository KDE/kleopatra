/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "certificatedetailsinputwidget.h"

#include <utils/userinfo.h>

#include <Libkleo/Dn>
#include <Libkleo/OidMap>
#include <Libkleo/Stl_Util>
#include <Libkleo/Validation>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QLabel>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QValidator>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Dialogs;

namespace
{
struct Line {
    QString attr;
    QString label;
    QString regex;
    QLineEdit *edit;
    std::shared_ptr<QValidator> validator;
    bool required;
};

QString attributeFromKey(QString key)
{
    return key.remove(QLatin1Char('!'));
}

QString attributeLabel(const QString &attr)
{
    if (attr.isEmpty()) {
        return QString();
    }
    const QString label = DN::attributeNameToLabel(attr);
    if (!label.isEmpty()) {
        return i18nc("Format string for the labels in the \"Your Personal Data\" page", "%1 (%2)", label, attr);
    } else {
        return attr;
    }
}

QLineEdit *addRow(QGridLayout *l, const QString &label, const QString &preset, const std::shared_ptr<QValidator> &validator, bool readonly, bool required)
{
    Q_ASSERT(l);

    auto lb = new QLabel(l->parentWidget());
    lb->setText(i18nc("interpunctation for labels", "%1:", label));

    auto le = new QLineEdit(l->parentWidget());
    le->setText(preset);
    if (validator) {
        le->setValidator(validator.get());
    }
    le->setReadOnly(readonly && le->hasAcceptableInput());

    auto reqLB = new QLabel(l->parentWidget());
    reqLB->setText(required ? i18n("(required)") : i18n("(optional)"));

    const int row = l->rowCount();
    l->addWidget(lb, row, 0);
    l->addWidget(le, row, 1);
    l->addWidget(reqLB, row, 2);
    return le;
}

bool hasIntermediateInput(const QLineEdit *le)
{
    QString text = le->text();
    int pos = le->cursorPosition();
    const QValidator *const v = le->validator();
    return v && v->validate(text, pos) == QValidator::Intermediate;
}

QString requirementsAreMet(const QList<Line> &lines)
{
    for (const Line &line : lines) {
        const QLineEdit *le = line.edit;
        if (!le) {
            continue;
        }
        qCDebug(KLEOPATRA_LOG) << "requirementsAreMet(): checking \"" << line.attr << "\" against \"" << le->text() << "\":";
        if (le->text().trimmed().isEmpty()) {
            if (line.required) {
                if (line.regex.isEmpty()) {
                    return xi18nc("@info", "<interface>%1</interface> is required, but empty.", line.label);
                } else {
                    return xi18nc("@info",
                                  "<interface>%1</interface> is required, but empty.<nl/>"
                                  "Local Admin rule: <icode>%2</icode>",
                                  line.label,
                                  line.regex);
                }
            }
        } else if (hasIntermediateInput(le)) {
            if (line.regex.isEmpty()) {
                return xi18nc("@info", "<interface>%1</interface> is incomplete.", line.label);
            } else {
                return xi18nc("@info",
                              "<interface>%1</interface> is incomplete.<nl/>"
                              "Local Admin rule: <icode>%2</icode>",
                              line.label,
                              line.regex);
            }
        } else if (!le->hasAcceptableInput()) {
            if (line.regex.isEmpty()) {
                return xi18nc("@info", "<interface>%1</interface> is invalid.", line.label);
            } else {
                return xi18nc("@info",
                              "<interface>%1</interface> is invalid.<nl/>"
                              "Local Admin rule: <icode>%2</icode>",
                              line.label,
                              line.regex);
            }
        }
    }
    return QString();
}
}

class CertificateDetailsInputWidget::Private
{
    friend class ::Kleo::Dialogs::CertificateDetailsInputWidget;
    CertificateDetailsInputWidget *const q;

    struct {
        QGridLayout *gridLayout;
        QList<Line> lines;
        QLineEdit *dn;
        QLabel *error;
    } ui;

public:
    Private(CertificateDetailsInputWidget *qq)
        : q(qq)
    {
        auto mainLayout = new QVBoxLayout(q);

        ui.gridLayout = new QGridLayout();
        mainLayout->addLayout(ui.gridLayout);

        createForm();

        mainLayout->addStretch(1);

        ui.dn = new QLineEdit();
        ui.dn->setFrame(false);
        ui.dn->setAlignment(Qt::AlignCenter);
        ui.dn->setReadOnly(true);
        mainLayout->addWidget(ui.dn);

        ui.error = new QLabel();
        {
            QSizePolicy sizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
            sizePolicy.setHorizontalStretch(0);
            sizePolicy.setVerticalStretch(0);
            sizePolicy.setHeightForWidth(ui.error->sizePolicy().hasHeightForWidth());
            ui.error->setSizePolicy(sizePolicy);
        }
        {
            QPalette palette;
            QBrush brush(QColor(255, 0, 0, 255));
            brush.setStyle(Qt::SolidPattern);
            palette.setBrush(QPalette::Active, QPalette::WindowText, brush);
            palette.setBrush(QPalette::Inactive, QPalette::WindowText, brush);
            QBrush brush1(QColor(114, 114, 114, 255));
            brush1.setStyle(Qt::SolidPattern);
            palette.setBrush(QPalette::Disabled, QPalette::WindowText, brush1);
            ui.error->setPalette(palette);
        }
        ui.error->setTextFormat(Qt::RichText);
        // set error label to have a fixed height of two lines:
        ui.error->setText(QStringLiteral("2<br>1"));
        ui.error->setFixedHeight(ui.error->minimumSizeHint().height());
        ui.error->clear();
        mainLayout->addWidget(ui.error);

        // select the preset text in the first line edit
        if (!ui.lines.empty()) {
            ui.lines.first().edit->selectAll();
        }

        // explicitly update DN and check requirements after setup is complete
        updateDN();
        checkRequirements();
    }

    ~Private()
    {
        // remember current attribute values as presets for next certificate
        KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("CertificateCreationWizard"));
        for (const Line &line : ui.lines) {
            const QString attr = attributeFromKey(line.attr);
            const QString value = line.edit->text().trimmed();
            config.writeEntry(attr, value);
        }
        config.sync();
    }

    void createForm()
    {
        static const QStringList defaultAttributeOrder = {
            QStringLiteral("CN!"),
            QStringLiteral("EMAIL!"),
            QStringLiteral("L"),
            QStringLiteral("OU"),
            QStringLiteral("O"),
            QStringLiteral("C"),
        };
        const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("CertificateCreationWizard"));

        const QStringList attrOrder = config.readEntry("DNAttributeOrder", defaultAttributeOrder);

        for (const QString &rawKey : attrOrder) {
            const QString key = rawKey.trimmed().toUpper();
            const QString attr = attributeFromKey(key);
            if (attr.isEmpty()) {
                continue;
            }
            const QString defaultPreset = //
                (attr == QLatin1StringView("CN"))      ? userFullName()
                : (attr == QLatin1StringView("EMAIL")) ? userEmailAddress()
                                                       : QString();
            const QString preset = config.readEntry(attr, defaultPreset);
            const bool required = key.endsWith(QLatin1Char('!'));
            const bool readonly = config.isEntryImmutable(attr);
            const QString label = config.readEntry(attr + QLatin1StringView("_label"), attributeLabel(attr));
            const QString regex = config.readEntry(attr + QLatin1StringView("_regex"));

            std::shared_ptr<QValidator> validator;
            if (attr == QLatin1StringView("EMAIL")) {
                validator = regex.isEmpty() ? Validation::email() : Validation::email(regex);
            } else if (!regex.isEmpty()) {
                validator = std::make_shared<QRegularExpressionValidator>(QRegularExpression{regex});
            }

            QLineEdit *le = addRow(ui.gridLayout, label, preset, validator, readonly, required);

            const Line line = {attr, label, regex, le, validator, required};
            ui.lines.push_back(line);

            if (attr != QLatin1StringView("EMAIL")) {
                connect(le, &QLineEdit::textChanged, le, [this]() {
                    updateDN();
                });
            }
            connect(le, &QLineEdit::textChanged, le, [this]() {
                checkRequirements();
            });
        }
    }

    void updateDN()
    {
        ui.dn->setText(cmsDN());
    }

    QString cmsDN() const
    {
        DN dn;
        for (const Line &line : ui.lines) {
            const QString text = line.edit->text().trimmed();
            if (text.isEmpty()) {
                continue;
            }
            QString attr = attributeFromKey(line.attr);
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

    void checkRequirements()
    {
        const QString error = requirementsAreMet(ui.lines);
        ui.error->setText(error);
        Q_EMIT q->validityChanged(error.isEmpty());
    }

    QLineEdit *attributeWidget(const QString &attribute)
    {
        for (const Line &line : ui.lines) {
            if (attributeFromKey(line.attr) == attribute) {
                return line.edit;
            }
        }
        qCWarning(KLEOPATRA_LOG) << "CertificateDetailsInputWidget: No widget for attribute" << attribute;
        return nullptr;
    }

    void setAttributeValue(const QString &attribute, const QString &value)
    {
        QLineEdit *w = attributeWidget(attribute);
        if (w) {
            w->setText(value);
        }
    }

    QString attributeValue(const QString &attribute)
    {
        const QLineEdit *w = attributeWidget(attribute);
        return w ? w->text().trimmed() : QString();
    }
};

CertificateDetailsInputWidget::CertificateDetailsInputWidget(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{
}

CertificateDetailsInputWidget::~CertificateDetailsInputWidget()
{
}

void CertificateDetailsInputWidget::setName(const QString &name)
{
    d->setAttributeValue(QStringLiteral("CN"), name);
}

void CertificateDetailsInputWidget::setEmail(const QString &email)
{
    d->setAttributeValue(QStringLiteral("EMAIL"), email);
}

QString CertificateDetailsInputWidget::email() const
{
    return d->attributeValue(QStringLiteral("EMAIL"));
}

QString CertificateDetailsInputWidget::dn() const
{
    return d->ui.dn->text();
}

#include "moc_certificatedetailsinputwidget.cpp"
