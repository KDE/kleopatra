/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "resultitemwidget.h"

#include "commands/command.h"
#include "commands/lookupcertificatescommand.h"
#include "crypto/decryptverifytask.h"
#include "view/htmllabel.h"
#include "view/urllabel.h"

#include <Libkleo/ApplicationPaletteWatcher>
#include <Libkleo/AuditLogEntry>
#include <Libkleo/AuditLogViewer>
#include <Libkleo/Classify>
#include <Libkleo/Formatting>
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
static KColorScheme::BackgroundRole colorForVisualCode(Task::Result::VisualCode code)
{
    switch (code) {
    case Task::Result::AllGood:
        return KColorScheme::PositiveBackground;
    case Task::Result::Warning:
        return KColorScheme::NormalBackground;
    case Task::Result::Danger:
        return KColorScheme::NegativeBackground;
    default:
        return KColorScheme::NormalBackground;
    }
}

struct ResultItemData {
    QPointer<QWidget> widget;
    KColorScheme::BackgroundRole backgroundRole;
};
}

class ResultItemWidget::Private
{
    ResultItemWidget *const q;

public:
    Private(const std::shared_ptr<const Task::Result> &result, ResultItemWidget *qq);

    void slotLinkActivated(const QString &);
    void updateShowDetailsLabel();
    void updateStyleSheets();

    void addIgnoreMDCButton(QBoxLayout *lay);

    void oneImportFinished();

    ApplicationPaletteWatcher m_appPaletteWatcher;
    QList<QPointer<QWidget>> m_mainStylesheetWidgets;
    QList<ResultItemData> m_itemStylesheetWidgets;
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

void ResultItemWidget::Private::updateStyleSheets()
{
    const QColor color = KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::NormalBackground).color();
    const QColor borderColor = (color.lightnessF() > 0.5) ? color.darker(150) : color.lighter(150);
    const QString styleSheet = QStringLiteral(
                                   "QFrame,QLabel { background-color: %1; margin: 0px; }"
                                   "QFrame#resultFrame{ border-color: %2; border-style: solid; border-radius: 3px; border-width: 1px }"
                                   "QLabel { padding: 5px; border-radius: 3px }")
                                   .arg(color.name())
                                   .arg(borderColor.name());
    for (auto &w : m_mainStylesheetWidgets) {
        w->setStyleSheet(styleSheet);
    }

    for (auto &item : m_itemStylesheetWidgets) {
        const QColor color = KColorScheme(QPalette::Active, KColorScheme::View).background(item.backgroundRole).color();
        const QColor borderColor = (color.lightnessF() > 0.5) ? color.darker(150) : color.lighter(150);
        const QString styleSheet = QStringLiteral(
                                       "QFrame { background-color: %1; margin: 0px; }"
                                       "QFrame { padding: 5px; border-radius: 3px; border-style: solid; border-width: 1px; border-color: %2; }")
                                       .arg(color.name())
                                       .arg(borderColor.name());
        item.widget->setStyleSheet(styleSheet);
    }
}

ResultItemWidget::Private::Private(const std::shared_ptr<const Task::Result> &result, ResultItemWidget *qq)
    : q(qq)
    , m_result(result)
{
    Q_ASSERT(m_result);

    auto topLayout = new QVBoxLayout(q);
    auto frame = new QFrame;
    frame->setObjectName(QLatin1StringView("resultFrame"));
    m_mainStylesheetWidgets.push_back(frame);
    topLayout->addWidget(frame);
    auto vlay = new QVBoxLayout(frame);
    auto layout = new QHBoxLayout();
    auto overview = new HtmlLabel;
    overview->setWordWrap(true);
    overview->setHtml(m_result->overview());
    m_mainStylesheetWidgets.push_back(overview);
    q->setFocusPolicy(overview->focusPolicy());
    q->setFocusProxy(overview);
    connect(overview, &QLabel::linkActivated, q, [this](const auto &link) {
        slotLinkActivated(link);
    });

    layout->addWidget(overview);
    vlay->addLayout(layout);

    auto actionLayout = new QVBoxLayout;
    layout->addLayout(actionLayout);

    addIgnoreMDCButton(actionLayout);

    m_auditLogLabel = new UrlLabel;
    connect(m_auditLogLabel, &QLabel::linkActivated, q, [this](const auto &link) {
        slotLinkActivated(link);
    });
    actionLayout->addWidget(m_auditLogLabel);
    m_mainStylesheetWidgets.push_back(m_auditLogLabel);

    for (const auto &detail : m_result.get()->detailsList()) {
        auto frame = new QFrame;
        auto row = new QHBoxLayout(frame);

        auto iconLabel = new QLabel;
        QIcon icon;
        if (detail.code == Task::Result::AllGood) {
            icon = Formatting::successIcon();
        } else if (detail.code == Task::Result::Warning) {
            icon = Formatting::warningIcon();
        } else {
            icon = Formatting::errorIcon();
        }
        iconLabel->setPixmap(icon.pixmap(32, 32));
        row->addWidget(iconLabel, 0);

        auto detailsLabel = new HtmlLabel;
        detailsLabel->setWordWrap(true);
        detailsLabel->setHtml(detail.details);
        iconLabel->setStyleSheet(QStringLiteral("QLabel {border-width: 0; }"));
        m_itemStylesheetWidgets.push_back({frame, colorForVisualCode(detail.code)});
        detailsLabel->setStyleSheet(QStringLiteral("QLabel {border-width: 0; }"));
        connect(detailsLabel, &QLabel::linkActivated, q, [this](const auto &link) {
            slotLinkActivated(link);
        });

        row->addWidget(detailsLabel, 1);
        vlay->addWidget(frame);
    }

    m_showButton = new QPushButton;
    m_showButton->setVisible(false);
    connect(m_showButton, &QAbstractButton::clicked, q, &ResultItemWidget::showButtonClicked);
    actionLayout->addWidget(m_showButton);

    m_closeButton = new QPushButton;
    KGuiItem::assign(m_closeButton, KStandardGuiItem::close());
    m_closeButton->setFixedSize(m_closeButton->sizeHint());
    connect(m_closeButton, &QAbstractButton::clicked, q, &ResultItemWidget::closeButtonClicked);
    actionLayout->addWidget(m_closeButton);
    m_closeButton->setVisible(false);

    layout->setStretch(0, 1);
    actionLayout->addStretch(-1);
    vlay->addStretch(-1);

    updateShowDetailsLabel();
    updateStyleSheets();
    connect(&m_appPaletteWatcher, &ApplicationPaletteWatcher::paletteChanged, q, [this]() {
        updateStyleSheets();
    });
}

ResultItemWidget::ResultItemWidget(const std::shared_ptr<const Task::Result> &result, QWidget *parent, Qt::WindowFlags flags)
    : QWidget(parent, flags)
    , d(new Private(result, this))
{
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

    if (url.scheme() == QStringLiteral("certificate")) {
        auto cmd = new Kleo::Commands::LookupCertificatesCommand(url.path(), nullptr);
        connect(cmd, &Kleo::Commands::LookupCertificatesCommand::canceled, q, [this]() {
            m_importCanceled = true;
        });
        connect(cmd, &Kleo::Commands::LookupCertificatesCommand::finished, q, [this]() {
            oneImportFinished();
        });
        cmd->setParentWidget(q);
        cmd->start();
        return;
    }
    qCWarning(KLEOPATRA_LOG) << "Unexpected link scheme: " << link;
}

void ResultItemWidget::showAuditLog()
{
    AuditLogViewer::showAuditLog(parentWidget(), d->m_result->auditLog());
}

#include "moc_resultitemwidget.cpp"
