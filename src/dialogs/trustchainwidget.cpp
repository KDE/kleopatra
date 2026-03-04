/*  SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "trustchainwidget.h"

#include "kleopatra_debug.h"

#include <KLocalizedString>

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/TreeWidget>

#include <QDialogButtonBox>
#include <QMenu>
#include <QPushButton>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <gpgme++/key.h>

using namespace Kleo;

class TrustChainWidget::Private
{
    TrustChainWidget *const q;

public:
    Private(TrustChainWidget *qq);

    GpgME::Key key;

    struct UI {
        TreeWidget *treeWidget;

        UI(QWidget *widget)
        {
            auto mainLayout = new QVBoxLayout{widget};
            mainLayout->setContentsMargins({});

            treeWidget = new TreeWidget{widget};
            treeWidget->setAccessibleName(i18nc("@label", "Certificate chain"));
            // Breeze draws no frame for scroll areas that are the only widget in a layout...unless we force it
            treeWidget->setProperty("_breeze_force_frame", true);
            treeWidget->setHeaderHidden(true);

            mainLayout->addWidget(treeWidget);
        }
    } ui;

private:
    void contextMenuRequested(const QPoint &pos)
    {
        auto menu = new QMenu;
        menu->setAttribute(Qt::WA_DeleteOnClose, true);
        menu->addAction(ui.treeWidget->copyCellContentsAction());
        menu->popup(ui.treeWidget->viewport()->mapToGlobal(pos));
    }
};

TrustChainWidget::Private::Private(TrustChainWidget *qq)
    : q(qq)
    , ui{qq}
{
    ui.treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui.treeWidget, &QWidget::customContextMenuRequested, q, [this](const auto &pos) {
        contextMenuRequested(pos);
    });
}

TrustChainWidget::TrustChainWidget(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{
}

TrustChainWidget::~TrustChainWidget()
{
}

void TrustChainWidget::setKey(const GpgME::Key &key)
{
    if (key.protocol() != GpgME::CMS) {
        qCDebug(KLEOPATRA_LOG) << "Trust chain is only supported for CMS keys";
        return;
    }

    d->key = key;
    d->ui.treeWidget->clear();
    const auto chain = Kleo::KeyCache::instance()->findIssuers(key, Kleo::KeyCache::RecursiveSearch | Kleo::KeyCache::IncludeSubject);
    if (chain.empty()) {
        return;
    }
    QTreeWidgetItem *last = nullptr;
    if (!chain.back().isRoot()) {
        last = new QTreeWidgetItem(d->ui.treeWidget);
        last->setText(0, i18n("Issuer Certificate Not Found (%1)", Kleo::Formatting::prettyDN(chain.back().issuerName())));
        const QBrush &fg = d->ui.treeWidget->palette().brush(QPalette::Disabled, QPalette::WindowText);
        last->setForeground(0, fg);
    }
    for (auto it = chain.rbegin(), end = chain.rend(); it != end; ++it) {
        last = last ? new QTreeWidgetItem(last) : new QTreeWidgetItem(d->ui.treeWidget);
        last->setText(0, Kleo::Formatting::prettyDN(it->userID(0).id()));
    }
    d->ui.treeWidget->expandAll();
}

GpgME::Key TrustChainWidget::key() const
{
    return d->key;
}

#include "moc_trustchainwidget.cpp"
