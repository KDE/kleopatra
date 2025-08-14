/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "welcomewidget.h"

#include "htmllabel.h"
#include "kleopatra_debug.h"
#include "kleopatraapplication.h"
#include "mainwindow.h"

#include <Libkleo/DocAction>

#include <KAboutData>

#include <QAction>
#include <QDesktopServices>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QToolButton>
#include <QVBoxLayout>

#include "commands/importcertificatefromfilecommand.h"
#include "commands/newopenpgpcertificatecommand.h"

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>
#include <KXmlGuiWindow>

static const QString templ = QStringLiteral(
    "<h3>%1</h3>" // Welcome
    "<p>%2<p/>" // Intro
    "<p>%7</p>" // (optional) VSD Text
    "<p>%8</p>" // (optional) Password explanation
    "<p>%3</p>" // Explanation
    "<ul><li>%4</li><li>%5</li></ul>" //
    "<p>%6</p>" // More info
    "<br />"
    "");

using namespace Kleo;

namespace
{
/**
 * A tool button that can be activated with the Enter and Return keys additionally to the Space key.
 */
class ToolButton : public QToolButton
{
    Q_OBJECT
public:
    using QToolButton::QToolButton;

protected:
    void keyPressEvent(QKeyEvent *e) override
    {
        switch (e->key()) {
        case Qt::Key_Enter:
        case Qt::Key_Return: {
            // forward as key press of Key_Select to QToolButton
            QKeyEvent alternateEvent{e->type(),
                                     Qt::Key_Select,
                                     e->modifiers(),
                                     e->nativeScanCode(),
                                     e->nativeVirtualKey(),
                                     e->nativeModifiers(),
                                     e->text(),
                                     e->isAutoRepeat(),
                                     static_cast<ushort>(e->count())};
            QToolButton::keyPressEvent(&alternateEvent);
            if (!alternateEvent.isAccepted()) {
                e->ignore();
            }
            break;
        }
        default:
            QToolButton::keyPressEvent(e);
        }
    }

    void keyReleaseEvent(QKeyEvent *e) override
    {
        switch (e->key()) {
        case Qt::Key_Enter:
        case Qt::Key_Return: {
            // forward as key release of Key_Select to QToolButton
            QKeyEvent alternateEvent{e->type(),
                                     Qt::Key_Select,
                                     e->modifiers(),
                                     e->nativeScanCode(),
                                     e->nativeVirtualKey(),
                                     e->nativeModifiers(),
                                     e->text(),
                                     e->isAutoRepeat(),
                                     static_cast<ushort>(e->count())};
            QToolButton::keyReleaseEvent(&alternateEvent);
            if (!alternateEvent.isAccepted()) {
                e->ignore();
            }
            break;
        }
        default:
            QToolButton::keyReleaseEvent(e);
        }
    }
};
}

class WelcomeWidget::Private
{
public:
    explicit Private(WelcomeWidget *qq)
        : q(qq)
    {
        auto vLay = new QVBoxLayout(q);
        auto hLay = new QHBoxLayout;

        const QString welcome = i18nc("%1 is version", "Welcome to Kleopatra %1", KAboutData::applicationData().version());
        const QString introduction = i18n("Kleopatra is a front-end for the crypto software <a href=\"https://gnupg.org\">GnuPG</a>.");

        QString keyExplanation = i18n("For most actions you need either a public key (certificate) or your own secret key.");

        const QString privateKeyExplanation = i18n("The secret key is needed to decrypt or sign.");
        const QString publicKeyExplanation = i18n("The public key can be used by others to verify your identity or encrypt to you.");

        const QString wikiUrl = i18nc("More info about public key cryptography, please link to your local version of Wikipedia",
                                      "https://en.wikipedia.org/wiki/Public-key_cryptography");
        QString learnMore = i18nc("%1 is a link to a wiki article", "You can learn more about this on <a href=\"%1\">Wikipedia</a>.", wikiUrl);

        QString vsdText;
        QString symExplanation;

        if (MainWindow::createSymmetricGuideAction(nullptr)->isEnabled()) {
            vsdText =
                i18nc("@info",
                      "With Kleopatra you can encrypt using different methods. Please follow the regulations for classified information of your organization.");
            symExplanation = i18nc("@info", "For password based encryption see this <a href=\"action:help_doc_symenc\">guide</a>.");
            keyExplanation = i18nc("@info", "For public key encryption you generally have to create your own key pair.");
            learnMore =
                i18nc("@info", "You can find step-by-step instructions for public key encryption in this <a href=\"action:help_doc_quickguide\">guide</a>.");
        }

        const auto labelText = templ.arg(welcome)
                                   .arg(introduction)
                                   .arg(keyExplanation)
                                   .arg(privateKeyExplanation)
                                   .arg(publicKeyExplanation)
                                   .arg(learnMore)
                                   .arg(vsdText)
                                   .arg(symExplanation);
        mLabel = new HtmlLabel{labelText, q};
        mLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);

        connect(mLabel, &QLabel::linkActivated, q, [](const auto &link) {
            QUrl url(link);
            if (url.scheme() == QStringLiteral("action")) {
                if (const auto action = KleopatraApplication::instance()->mainWindow()->action(url.path())) {
                    action->trigger();
                } else {
                    qCWarning(KLEOPATRA_LOG) << "action" << url.path() << "not found";
                }
                return;
            }
            QDesktopServices::openUrl(url);
        });
        auto genKeyAction = new QAction(q);
        genKeyAction->setText(i18n("New Key Pair..."));
        genKeyAction->setIcon(QIcon::fromTheme(QStringLiteral("view-certificate-add")));

        auto importAction = new QAction(q);
        importAction->setText(i18n("Import..."));
        importAction->setIcon(QIcon::fromTheme(QStringLiteral("view-certificate-import")));

        connect(importAction, &QAction::triggered, q, [this]() {
            import();
        });
        connect(genKeyAction, &QAction::triggered, q, [this]() {
            generate();
        });

        mGenerateBtn = new ToolButton{q};
        mGenerateBtn->setDefaultAction(genKeyAction);
        mGenerateBtn->setIconSize(QSize(64, 64));
        mGenerateBtn->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
        const auto generateBtnDescription = kxi18nc("@info",
                                                    "Create a new OpenPGP key pair.<nl/>"
                                                    "To create an S/MIME certificate request use "
                                                    "<interface>New S/MIME Certification Request</interface> "
                                                    "from the <interface>File</interface> menu instead.");
        mGenerateBtn->setToolTip(generateBtnDescription.toString());
        mGenerateBtn->setAccessibleDescription(generateBtnDescription.toString(Kuit::PlainText));

        KConfigGroup restrictions(KSharedConfig::openConfig(), QStringLiteral("KDE Action Restrictions"));
        mGenerateBtn->setEnabled(restrictions.readEntry("action/file_new_certificate", true));

        mImportBtn = new ToolButton{q};
        mImportBtn->setDefaultAction(importAction);
        mImportBtn->setIconSize(QSize(64, 64));
        mImportBtn->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
        const auto importBtnDescription = kxi18nc("@info",
                                                  "Import certificate from a file.<nl/>"
                                                  "To import from a public keyserver use <interface>Lookup on Server</interface> instead.");
        mImportBtn->setToolTip(importBtnDescription.toString());
        mImportBtn->setAccessibleDescription(importBtnDescription.toString(Kuit::PlainText));
        mImportBtn->setEnabled(restrictions.readEntry("action/file_import_certificate", true));

        auto btnLayout = new QHBoxLayout;
        btnLayout->addStretch(-1);
        btnLayout->addWidget(mGenerateBtn);
        btnLayout->addWidget(mImportBtn);
        btnLayout->addStretch(-1);

        vLay->addStretch(-1);
        vLay->addLayout(hLay);
        vLay->addLayout(btnLayout);
        vLay->addStretch(-1);

        hLay->addStretch(-1);
        hLay->addWidget(mLabel);
        hLay->addStretch(-1);
    }

    void import()
    {
        mImportBtn->setEnabled(false);
        auto cmd = new Kleo::ImportCertificateFromFileCommand();
        cmd->setParentWidget(q);

        QObject::connect(cmd, &Kleo::ImportCertificateFromFileCommand::finished, q, [this]() {
            mImportBtn->setEnabled(true);
        });
        cmd->start();
    }

    void generate()
    {
        mGenerateBtn->setEnabled(false);
        auto cmd = new NewOpenPGPCertificateCommand;
        cmd->setParentWidget(q);

        QObject::connect(cmd, &NewOpenPGPCertificateCommand::finished, q, [this]() {
            mGenerateBtn->setEnabled(true);
        });
        cmd->start();
    }

    WelcomeWidget *const q;
    HtmlLabel *mLabel = nullptr;
    ToolButton *mGenerateBtn = nullptr;
    ToolButton *mImportBtn = nullptr;
};

WelcomeWidget::WelcomeWidget(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{
}

void WelcomeWidget::focusFirstChild(Qt::FocusReason reason)
{
    d->mLabel->setFocus(reason);
}

#include "welcomewidget.moc"

#include "moc_welcomewidget.cpp"
