/* -*- mode: c++; c-basic-offset:4 -*-
    crypto/gui/resultitemwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "resultitemwidget.h"

#include "commands/command.h"
#include "commands/importcertificatefromfilecommand.h"
#include "commands/lookupcertificatescommand.h"
#include "crypto/decryptverifytask.h"
#include "view/htmllabel.h"
#include "view/urllabel.h"

#include <Libkleo/AuditLogEntry>
#include <Libkleo/AuditLogViewer>
#include <Libkleo/Classify>
#include <Libkleo/SystemInfo>

#include <gpgme++/decryptionresult.h>
#include <gpgme++/key.h>

#include "kleopatra_debug.h"
#include <KColorScheme>
#include <KGuiItem>
#include <KLocalizedString>
#include <KStandardGuiItem>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

namespace
{
// TODO move out of here
static QColor colorForVisualCode(Task::Result::VisualCode code)
{
    switch (code) {
    case Task::Result::AllGood:
        return KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::PositiveBackground).color();
    case Task::Result::NeutralError:
    case Task::Result::Warning:
        return KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::NormalBackground).color();
    case Task::Result::Danger:
        return KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::NegativeBackground).color();
    case Task::Result::NeutralSuccess:
    default:
        return QColor(0x00, 0x80, 0xFF); // light blue
    }
}
static QColor txtColorForVisualCode(Task::Result::VisualCode code)
{
    switch (code) {
    case Task::Result::AllGood:
    case Task::Result::NeutralError:
    case Task::Result::Warning:
        return KColorScheme(QPalette::Active, KColorScheme::View).foreground(KColorScheme::NormalText).color();
    case Task::Result::Danger:
        return KColorScheme(QPalette::Active, KColorScheme::View).foreground(KColorScheme::NegativeText).color();
    case Task::Result::NeutralSuccess:
    default:
        return QColor(0xFF, 0xFF, 0xFF); // white
    }
}
}

class ResultItemWidget::Private
{
    ResultItemWidget *const q;

public:
    explicit Private(const std::shared_ptr<const Task::Result> &result, ResultItemWidget *qq)
        : q(qq)
        , m_result(result)
    {
        Q_ASSERT(m_result);
    }

    void slotLinkActivated(const QString &);
    void updateShowDetailsLabel();

    void addKeyImportButton(QBoxLayout *lay, bool search);
    void addIgnoreMDCButton(QBoxLayout *lay);

    void oneImportFinished();

    const std::shared_ptr<const Task::Result> m_result;
    UrlLabel *m_auditLogLabel = nullptr;
    QPushButton *m_closeButton = nullptr;
    QPushButton *m_showButton = nullptr;
    bool m_importCanceled = false;
};

void ResultItemWidget::Private::oneImportFinished()
{
    if (m_importCanceled) {
        return;
    }
    if (m_result->parentTask()) {
        m_result->parentTask()->start();
    }
    q->setVisible(false);
}

void ResultItemWidget::Private::addIgnoreMDCButton(QBoxLayout *lay)
{
    if (!m_result || !lay) {
        return;
    }

    const auto dvResult = dynamic_cast<const DecryptVerifyResult *>(m_result.get());
    if (!dvResult) {
        return;
    }
    const auto decResult = dvResult->decryptionResult();

    if (decResult.isNull() || !decResult.error() || !decResult.isLegacyCipherNoMDC()) {
        return;
    }

    auto btn = new QPushButton(i18nc("@action:button", "Force decryption"));
    btn->setFixedSize(btn->sizeHint());

    connect(btn, &QPushButton::clicked, q, [this]() {
        if (m_result->parentTask()) {
            const auto dvTask = dynamic_cast<DecryptVerifyTask *>(m_result->parentTask().data());
            dvTask->setIgnoreMDCError(true);
            dvTask->start();
            q->setVisible(false);
        } else {
            qCWarning(KLEOPATRA_LOG) << "Failed to get parent task";
        }
    });
    lay->addWidget(btn);
}

void ResultItemWidget::Private::addKeyImportButton(QBoxLayout *lay, bool search)
{
    if (!m_result || !lay) {
        return;
    }

    const auto dvResult = dynamic_cast<const DecryptVerifyResult *>(m_result.get());
    if (!dvResult) {
        return;
    }
    const auto verifyResult = dvResult->verificationResult();

    if (verifyResult.isNull()) {
        return;
    }

    for (const auto &sig : verifyResult.signatures()) {
        if (!(sig.summary() & GpgME::Signature::KeyMissing)) {
            continue;
        }

        auto btn = new QPushButton;
        QString suffix;
        const auto keyid = QLatin1StringView(sig.fingerprint());
        if (verifyResult.numSignatures() > 1) {
            suffix = QLatin1Char(' ') + keyid;
        }
        btn = new QPushButton(search ? i18nc("1 is optional keyid. No space is intended as it can be empty.", "Search%1", suffix)
                                     : i18nc("1 is optional keyid. No space is intended as it can be empty.", "Import%1", suffix));

        if (search) {
            btn->setIcon(QIcon::fromTheme(QStringLiteral("edit-find")));
            connect(btn, &QPushButton::clicked, q, [this, btn, keyid]() {
                btn->setEnabled(false);
                m_importCanceled = false;
                auto cmd = new Kleo::Commands::LookupCertificatesCommand(keyid, nullptr);
                connect(cmd, &Kleo::Commands::LookupCertificatesCommand::canceled, q, [this]() {
                    m_importCanceled = true;
                });
                connect(cmd, &Kleo::Commands::LookupCertificatesCommand::finished, q, [this, btn]() {
                    btn->setEnabled(true);
                    oneImportFinished();
                });
                cmd->setParentWidget(q);
                cmd->start();
            });
        } else {
            btn->setIcon(QIcon::fromTheme(QStringLiteral("view-certificate-import")));
            connect(btn, &QPushButton::clicked, q, [this, btn]() {
                btn->setEnabled(false);
                m_importCanceled = false;
                auto cmd = new Kleo::ImportCertificateFromFileCommand();
                connect(cmd, &Kleo::ImportCertificateFromFileCommand::canceled, q, [this]() {
                    m_importCanceled = true;
                });
                connect(cmd, &Kleo::ImportCertificateFromFileCommand::finished, q, [this, btn]() {
                    btn->setEnabled(true);
                    oneImportFinished();
                });
                cmd->setParentWidget(q);
                cmd->start();
            });
        }
        btn->setFixedSize(btn->sizeHint());
        lay->addWidget(btn);
    }
}

static QUrl auditlog_url_template()
{
    QUrl url(QStringLiteral("kleoresultitem://showauditlog"));
    return url;
}

void ResultItemWidget::Private::updateShowDetailsLabel()
{
    const auto auditLogUrl = m_result->auditLog().asUrl(auditlog_url_template());
    const auto auditLogLinkText = m_result->hasError() ? i18n("Diagnostics") //
                                                       : i18nc("The Audit Log is a detailed error log from the gnupg backend", "Show Audit Log");
    m_auditLogLabel->setUrl(auditLogUrl, auditLogLinkText);
    m_auditLogLabel->setVisible(!auditLogUrl.isEmpty());
}

ResultItemWidget::ResultItemWidget(const std::shared_ptr<const Task::Result> &result, QWidget *parent, Qt::WindowFlags flags)
    : QWidget(parent, flags)
    , d(new Private(result, this))
{
    const QColor color = colorForVisualCode(d->m_result->code());
    const QColor txtColor = txtColorForVisualCode(d->m_result->code());
    const QColor linkColor = SystemInfo::isHighContrastModeActive() ? QColor{} : txtColor;
    const QString styleSheet = SystemInfo::isHighContrastModeActive()
        ? QStringLiteral(
              "QFrame,QLabel { margin: 0px; }"
              "QFrame#resultFrame{ border-style: solid; border-radius: 3px; border-width: 1px }"
              "QLabel { padding: 5px; border-radius: 3px }")
        : QStringLiteral(
              "QFrame,QLabel { background-color: %1; margin: 0px; }"
              "QFrame#resultFrame{ border-color: %2; border-style: solid; border-radius: 3px; border-width: 1px }"
              "QLabel { color: %3; padding: 5px; border-radius: 3px }")
              .arg(color.name())
              .arg(color.darker(150).name())
              .arg(txtColor.name());
    auto topLayout = new QVBoxLayout(this);
    auto frame = new QFrame;
    frame->setObjectName(QLatin1StringView("resultFrame"));
    frame->setStyleSheet(styleSheet);
    topLayout->addWidget(frame);
    auto layout = new QHBoxLayout(frame);
    auto vlay = new QVBoxLayout();
    auto overview = new HtmlLabel;
    overview->setWordWrap(true);
    overview->setHtml(d->m_result->overview());
    overview->setStyleSheet(styleSheet);
    overview->setLinkColor(linkColor);
    setFocusPolicy(overview->focusPolicy());
    setFocusProxy(overview);
    connect(overview, &QLabel::linkActivated, this, [this](const auto &link) {
        d->slotLinkActivated(link);
    });

    vlay->addWidget(overview);
    layout->addLayout(vlay);

    auto actionLayout = new QVBoxLayout;
    layout->addLayout(actionLayout);

    d->addKeyImportButton(actionLayout, false);
    // TODO: Only show if auto-key-retrieve is not set.
    d->addKeyImportButton(actionLayout, true);

    d->addIgnoreMDCButton(actionLayout);

    d->m_auditLogLabel = new UrlLabel;
    connect(d->m_auditLogLabel, &QLabel::linkActivated, this, [this](const auto &link) {
        d->slotLinkActivated(link);
    });
    actionLayout->addWidget(d->m_auditLogLabel);
    d->m_auditLogLabel->setStyleSheet(styleSheet);
    d->m_auditLogLabel->setLinkColor(linkColor);

    auto detailsLabel = new HtmlLabel;
    detailsLabel->setWordWrap(true);
    detailsLabel->setHtml(d->m_result->details());
    detailsLabel->setStyleSheet(styleSheet);
    detailsLabel->setLinkColor(linkColor);
    connect(detailsLabel, &QLabel::linkActivated, this, [this](const auto &link) {
        d->slotLinkActivated(link);
    });
    vlay->addWidget(detailsLabel);

    d->m_showButton = new QPushButton;
    d->m_showButton->setVisible(false);
    connect(d->m_showButton, &QAbstractButton::clicked, this, &ResultItemWidget::showButtonClicked);
    actionLayout->addWidget(d->m_showButton);

    d->m_closeButton = new QPushButton;
    KGuiItem::assign(d->m_closeButton, KStandardGuiItem::close());
    d->m_closeButton->setFixedSize(d->m_closeButton->sizeHint());
    connect(d->m_closeButton, &QAbstractButton::clicked, this, &ResultItemWidget::closeButtonClicked);
    actionLayout->addWidget(d->m_closeButton);
    d->m_closeButton->setVisible(false);

    layout->setStretch(0, 1);
    actionLayout->addStretch(-1);
    vlay->addStretch(-1);

    d->updateShowDetailsLabel();
    setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Maximum);
}

ResultItemWidget::~ResultItemWidget()
{
}

void ResultItemWidget::showCloseButton(bool show)
{
    d->m_closeButton->setVisible(show);
}

void ResultItemWidget::setShowButton(const QString &text, bool show)
{
    d->m_showButton->setText(text);
    d->m_showButton->setVisible(show);
}

bool ResultItemWidget::hasErrorResult() const
{
    return d->m_result->hasError();
}

void ResultItemWidget::Private::slotLinkActivated(const QString &link)
{
    Q_ASSERT(m_result);
    qCDebug(KLEOPATRA_LOG) << "Link activated: " << link;
    if (link.startsWith(QLatin1StringView("key:"))) {
        auto split = link.split(QLatin1Char(':'));
        auto fpr = split.value(1);
        if (split.size() == 2 && isFingerprint(fpr)) {
            /* There might be a security consideration here if somehow
             * a short keyid is used in a link and it collides with another.
             * So we additionally check that it really is a fingerprint. */
            auto cmd = Command::commandForQuery(fpr);
            cmd->setParentWId(q->effectiveWinId());
            cmd->start();
        } else {
            qCWarning(KLEOPATRA_LOG) << "key link invalid " << link;
        }
        return;
    }

    const QUrl url(link);

    if (url.host() == QLatin1StringView("showauditlog")) {
        q->showAuditLog();
        return;
    }
    qCWarning(KLEOPATRA_LOG) << "Unexpected link scheme: " << link;
}

void ResultItemWidget::showAuditLog()
{
    AuditLogViewer::showAuditLog(parentWidget(), d->m_result->auditLog());
}

#include "moc_resultitemwidget.cpp"
