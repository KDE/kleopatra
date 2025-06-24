// SPDX-FileCopyrightText: 2025 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "importedcertificatesdialog.h"

#include "commands/detailscommand.h"
#include "commands/importcertificatescommand_p.h"
#include "view/keytreeview.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/KeyListModel>
#include <Libkleo/KeyListSortFilterProxyModel>

#include <gpgme++/importresult.h>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QPushButton>
#include <QVBoxLayout>

using namespace Kleo;
using namespace GpgME;

class ImportResultProxyModel : public AbstractKeyListSortFilterProxyModel
{
    Q_OBJECT
public:
    ImportResultProxyModel(const std::vector<ImportResultData> &results, QObject *parent = nullptr)
        : AbstractKeyListSortFilterProxyModel(parent)
    {
        updateFindCache(results);
    }

    ~ImportResultProxyModel() override
    {
    }

    ImportResultProxyModel *clone() const override
    {
        // compiler-generated copy ctor is fine!
        return new ImportResultProxyModel(*this);
    }

protected:
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid() || role != Qt::ToolTipRole) {
            return AbstractKeyListSortFilterProxyModel::data(index, role);
        }
        const QString fpr = index.data(KeyList::FingerprintRole).toString();
        // find information:
        const std::vector<Import>::const_iterator it =
            Kleo::binary_find(m_importsByFingerprint.begin(), m_importsByFingerprint.end(), fpr.toLatin1().constData(), ByImportFingerprint<std::less>());
        if (it == m_importsByFingerprint.end()) {
            return AbstractKeyListSortFilterProxyModel::data(index, role);
        } else {
            QStringList rv;
            const auto ids = m_idsByFingerprint[it->fingerprint()];
            rv.reserve(ids.size());
            std::copy(ids.cbegin(), ids.cend(), std::back_inserter(rv));
            return Formatting::importMetaData(*it, rv);
        }
    }
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override
    {
        //
        // 0. Keep parents of matching children:
        //
        const QModelIndex index = sourceModel()->index(source_row, 0, source_parent);
        Q_ASSERT(index.isValid());
        for (int i = 0, end = sourceModel()->rowCount(index); i != end; ++i)
            if (filterAcceptsRow(i, index)) {
                return true;
            }
        //
        // 1. Check that this is an imported key:
        //
        const QString fpr = index.data(KeyList::FingerprintRole).toString();

        return std::binary_search(m_importsByFingerprint.begin(), m_importsByFingerprint.end(), fpr.toLatin1().constData(), ByImportFingerprint<std::less>());
    }

private:
    void updateFindCache(const std::vector<ImportResultData> &results)
    {
        m_importsByFingerprint.clear();
        m_idsByFingerprint.clear();
        m_results = results;
        for (const auto &r : results) {
            const std::vector<Import> imports = r.result.imports();
            m_importsByFingerprint.insert(m_importsByFingerprint.end(), imports.begin(), imports.end());
            for (std::vector<Import>::const_iterator it = imports.begin(), end = imports.end(); it != end; ++it) {
                m_idsByFingerprint[it->fingerprint()].insert(r.id);
            }
        }
        std::sort(m_importsByFingerprint.begin(), m_importsByFingerprint.end(), ByImportFingerprint<std::less>());
    }

private:
    mutable std::vector<Import> m_importsByFingerprint;
    mutable std::map<const char *, std::set<QString>, ByImportFingerprint<std::less>> m_idsByFingerprint;
    std::vector<ImportResultData> m_results;
};

ImportedCertificatesDialog::ImportedCertificatesDialog(const std::vector<ImportResultData> &res, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(i18nc("@title:dialog as in 'list of certificates that were imported'", "Imported Certificates"));
    setAttribute(Qt::WA_DeleteOnClose);

    auto configGroup = KConfigGroup(KSharedConfig::openStateConfig(), QStringLiteral("ImportedCertificatesDialog"));
    const auto size = configGroup.readEntry("Size", QSize(730, 280));
    if (size.isValid()) {
        resize(size);
    }

    auto layout = new QVBoxLayout(this);
    auto model = AbstractKeyListModel::createFlatKeyListModel(this);
    model->useKeyCache(true, KeyList::AllKeys);
    auto proxyModel = new ImportResultProxyModel(res);
    proxyModel->setSourceModel(model);
    auto keyTreeView = new KeyTreeView({}, {}, proxyModel, this, {});
    keyTreeView->setFlatModel(model);
    keyTreeView->restoreLayout(configGroup);
    connect(keyTreeView->view(), &QAbstractItemView::doubleClicked, keyTreeView->view(), [this](const auto &index) {
        auto detailsCommand = new Commands::DetailsCommand(index.data(Kleo::KeyList::KeyRole).template value<Key>());
        detailsCommand->setParentWidget(this);
        detailsCommand->start();
    });
    layout->addWidget(keyTreeView);

    connect(this, &QDialog::finished, this, [this]() {
        KConfigGroup config(KSharedConfig::openStateConfig(), QStringLiteral("ImportedCertificatesDialog"));
        config.writeEntry("Size", this->size());
        config.sync();
    });
    show();
}

#include "importedcertificatesdialog.moc"
#include "moc_importedcertificatesdialog.cpp"
