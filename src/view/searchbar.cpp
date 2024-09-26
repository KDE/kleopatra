/* -*- mode: c++; c-basic-offset: 4; indent-tabs-mode: nil; -*-
    view/searchbar.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "searchbar.h"

#include <Libkleo/Algorithm>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyFilter>
#include <Libkleo/KeyFilterManager>

#include <KLocalizedString>

#include <QComboBox>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QSortFilterProxyModel>

#include <gpgme++/key.h>

#include "kleopatra_debug.h"

using namespace Kleo;

namespace
{

class ProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    using QSortFilterProxyModel::QSortFilterProxyModel;

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override
    {
        const QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);
        const auto matchContexts = qvariant_cast<KeyFilter::MatchContexts>(sourceModel()->data(index, KeyFilterManager::FilterMatchContextsRole));
        return matchContexts & KeyFilter::Filtering;
    }
};

}

class SearchBar::Private
{
    friend class ::Kleo::SearchBar;
    SearchBar *const q;

public:
    explicit Private(SearchBar *qq);
    ~Private();

private:
    std::shared_ptr<KeyFilter> keyFilter(int idx) const
    {
        return proxyModel->index(idx, 0).data(KeyFilterManager::FilterRole).value<std::shared_ptr<KeyFilter>>();
    }

    std::shared_ptr<KeyFilter> currentKeyFilter() const
    {
        return keyFilter(combo->currentIndex());
    }

    QString currentKeyFilterID() const
    {
        if (const std::shared_ptr<KeyFilter> f = currentKeyFilter()) {
            return f->id();
        } else {
            return QString();
        }
    }

    static auto notCertifiedKeysFilterId()
    {
        static const QString filterId = QStringLiteral("not-certified-certificates");
        return filterId;
    }

    void listNotCertifiedKeys() const
    {
        lineEdit->clear();
        combo->setCurrentIndex(combo->findData(notCertifiedKeysFilterId()));
        Q_EMIT q->keyFilterChanged(keyFilter(combo->currentIndex()));
    }

    void showOrHideCertifyButton() const
    {
        if (!KeyCache::instance()->initialized()) {
            return;
        }
        const auto filter = KeyFilterManager::instance()->keyFilterByID(notCertifiedKeysFilterId());
        if (filter) {
            if (std::ranges::any_of(KeyCache::instance()->keys(), [filter](const auto &key) {
                    return filter->matches(key, KeyFilter::Filtering);
                })) {
                certifyButton->show();
                return;
            }
        } else {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Key filter with id" << notCertifiedKeysFilterId() << "not found";
        }
        certifyButton->hide();
    }

private:
    ProxyModel *proxyModel;
    KeyFilterModel *keyFilterModel;
    QLineEdit *lineEdit;
    QComboBox *combo;
    QPushButton *certifyButton;
    int comboSavedIndex = -1;
};

SearchBar::Private::Private(SearchBar *qq)
    : q(qq)
{
    auto layout = new QHBoxLayout(q);
    layout->setContentsMargins(0, 0, 0, 0);
    lineEdit = new QLineEdit(q);
    lineEdit->setClearButtonEnabled(true);
    lineEdit->setPlaceholderText(i18nc("@info:placeholder", "Enter search term"));
    lineEdit->setAccessibleName(i18n("Filter certificates by text"));
    lineEdit->setToolTip(i18nc("@info:tooltip", "Show only certificates that match the entered search term."));
    layout->addWidget(lineEdit, /*stretch=*/1);
    combo = new QComboBox(q);
    combo->setAccessibleName(i18n("Filter certificates by category"));
    combo->setToolTip(i18nc("@info:tooltip", "Show only certificates that belong to the selected category."));
    layout->addWidget(combo);
    certifyButton = new QPushButton(q);
    certifyButton->setIcon(QIcon::fromTheme(QStringLiteral("security-medium")));
    certifyButton->setAccessibleName(i18n("Show not certified certificates"));
    certifyButton->setToolTip(
        i18n("Some certificates are not yet certified. "
             "Click here to see a list of these certificates."
             "<br/><br/>"
             "Certification is required to make sure that the certificates "
             "actually belong to the identity they claim to belong to."));
    certifyButton->hide();
    layout->addWidget(certifyButton);

    keyFilterModel = new KeyFilterModel{q};
    keyFilterModel->setSourceModel(KeyFilterManager::instance()->model());

    proxyModel = new ProxyModel{q};
    proxyModel->setSourceModel(keyFilterModel);

    proxyModel->sort(0, Qt::AscendingOrder);
    combo->setModel(proxyModel);

    connect(proxyModel, &QAbstractItemModel::modelAboutToBeReset, q, [this]() {
        comboSavedIndex = combo->currentIndex();
    });

    connect(proxyModel, &QAbstractItemModel::modelReset, q, [this]() {
        if (comboSavedIndex != -1) {
            combo->setCurrentIndex(comboSavedIndex);
        }
    });

    Q_SET_OBJECT_NAME(layout);
    Q_SET_OBJECT_NAME(lineEdit);
    Q_SET_OBJECT_NAME(combo);
    Q_SET_OBJECT_NAME(certifyButton);

    connect(lineEdit, &QLineEdit::textChanged, q, &SearchBar::stringFilterChanged);
    connect(combo, &QComboBox::currentIndexChanged, q, [this]() {
        Q_EMIT q->keyFilterChanged(combo->currentData(KeyFilterManager::FilterRole).value<std::shared_ptr<KeyFilter>>());
    });
    connect(certifyButton, &QPushButton::clicked, q, [this]() {
        listNotCertifiedKeys();
    });

    connect(KeyCache::instance().get(), &KeyCache::keyListingDone, q, [this]() {
        showOrHideCertifyButton();
    });
    showOrHideCertifyButton();
}

SearchBar::Private::~Private()
{
}

SearchBar::SearchBar(QWidget *parent, Qt::WindowFlags f)
    : QWidget(parent, f)
    , d(new Private(this))
{
}

SearchBar::~SearchBar()
{
}

void SearchBar::updateClickMessage(const QString &shortcutStr)
{
    d->lineEdit->setPlaceholderText(i18nc("@info:placeholder", "Enter search term <%1>", shortcutStr));
}

// slot
void SearchBar::setStringFilter(const QString &filter)
{
    d->lineEdit->setText(filter);
}

// slot
void SearchBar::setKeyFilter(const std::shared_ptr<KeyFilter> &kf)
{
    if (!kf) {
        return;
    }

    auto index = d->combo->findData(kf->id());
    if (index != -1) {
        d->combo->setCurrentIndex(index);
    } else {
        d->combo->setCurrentIndex(0);
    }
}

// slot
void SearchBar::setChangeStringFilterEnabled(bool on)
{
    d->lineEdit->setEnabled(on);
}

// slot
void SearchBar::setChangeKeyFilterEnabled(bool on)
{
    d->combo->setEnabled(on);
}

QLineEdit *SearchBar::lineEdit() const
{
    return d->lineEdit;
}

void SearchBar::addCustomKeyFilter(const std::shared_ptr<KeyFilter> &keyFilter)
{
    d->keyFilterModel->prependCustomFilter(keyFilter);
    d->proxyModel->sort(0, Qt::AscendingOrder);
}

#include "moc_searchbar.cpp"
#include "searchbar.moc"
