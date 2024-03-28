// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include <config-kleopatra.h>

#include "certificatedumpwidget.h"

#include "commands/dumpcertificatecommand.h"

#include <kleopatra_debug.h>

#include <Libkleo/GnuPG>

#include <gpgme++/context.h>
#include <gpgme++/key.h>

#include <KLocalizedString>

#include <QTextEdit>
#include <QVBoxLayout>

class CertificateDumpWidget::Private
{
    CertificateDumpWidget *const q;

public:
    Private(CertificateDumpWidget *qq)
        : q{qq}
        , ui{qq}
    {
    }

    GpgME::Key key;
    struct UI {
        QVBoxLayout *mainLayout;
        QTextEdit *textEdit;

        UI(QWidget *widget)
        {
            mainLayout = new QVBoxLayout{widget};
            mainLayout->setContentsMargins({});
            mainLayout->setSpacing(0);

            textEdit = new QTextEdit(widget);
            textEdit->setReadOnly(true);
            textEdit->setFontFamily(QStringLiteral("monospace"));
            mainLayout->addWidget(textEdit);
        }
    } ui;
};

CertificateDumpWidget::CertificateDumpWidget(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{
}

CertificateDumpWidget::~CertificateDumpWidget() = default;

void CertificateDumpWidget::setKey(const GpgME::Key &key)
{
    d->key = key;
    auto command = new Kleo::Commands::DumpCertificateCommand(key);
    command->setUseDialog(false);
    connect(command, &Kleo::Command::finished, this, [command, this]() {
        d->ui.textEdit->setText(command->output().join(u'\n'));
    });
    command->start();
}

GpgME::Key CertificateDumpWidget::key() const
{
    return d->key;
}

#include "moc_certificatedumpwidget.cpp"
