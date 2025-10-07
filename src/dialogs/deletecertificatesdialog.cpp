/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "deletecertificatesdialog.h"

#include <view/keytreeview.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyListModel>
#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>
#include <KStandardGuiItem>

#include <QCursor>
#include <QDialogButtonBox>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QScreen>
#include <QTreeView>
#include <QVBoxLayout>
#include <QWhatsThis>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace GpgME;

static int maxRecommendedWidth(QList<QListWidget *> widgets)
{
    if (widgets.isEmpty()) {
        return -1;
    }
    auto metrics = widgets[0]->fontMetrics();
    auto maxWidth = -1;
    for (const auto &widget : widgets) {
        for (int i = 0; i < widget->count(); i++) {
            auto width = metrics.boundingRect(widget->item(i)->text()).width();
            if (width > maxWidth) {
                maxWidth = width;
            }
        }
    }
    return std::min(widgets[0]->screen()->size().width(), maxWidth);
}

class DeleteCertificatesDialog::Private
{
    friend class ::Kleo::Dialogs::DeleteCertificatesDialog;
    DeleteCertificatesDialog *const q;

public:
    explicit Private(DeleteCertificatesDialog *qq)
        : q(qq)
        , ui(q)
    {
    }

    void readConfig()
    {
        KConfigGroup dialog(KSharedConfig::openStateConfig(), QStringLiteral("DeleteCertificatesDialog"));
        const QSize size = dialog.readEntry("Size", QSize(600, 400));
        if (size.isValid()) {
            q->resize(size);
        }
    }

    void writeConfig()
    {
        KConfigGroup dialog(KSharedConfig::openStateConfig(), QStringLiteral("DeleteCertificatesDialog"));
        dialog.writeEntry("Size", q->size());
        dialog.sync();
    }

    void checkGroups(const std::vector<Key> &keys)
    {
        if (keys.empty()) {
            return;
        }
        const auto &groups = KeyCache::instance()->groups();
        QSet<QString> foundGroups;
        for (const auto &key : keys) {
            for (const auto &group : groups) {
                if (group.keys().contains(key)) {
                    if (ui.groupsList->findItems(group.name(), Qt::MatchExactly).isEmpty()) {
                        ui.groupsList->addItem(group.name());
                    }
                }
            }
        }

        ui.groupsLB.setVisible(ui.groupsList->count() > 0);
        ui.groupsList->setVisible(ui.groupsList->count() > 0);

        ui.groupsList->setVisible(ui.groupsList->count() > 0);
        if (ui.groupsList->count() == 1) {
            ui.groupsLB.setText(i18np("The certificate is part of a group. Deleting it may prevent this recipient from decrypting messages to:",
                                      "The certificates are part of a group. Deleting them may prevent these recipients from decrypting messages to:",
                                      selectedKeys.size() + unselectedKeys.size()));
        } else {
            ui.groupsLB.setText(i18np("The certificate is part of several groups. Deleting it may prevent the recipient from decrypting messages to:",
                                      "The certificates are part of several groups. Deleting them may prevent the recipients from decrypting messages to:",
                                      selectedKeys.size() + unselectedKeys.size()));
        }
        q->resize({maxRecommendedWidth({ui.selectedList, ui.unselectedList, ui.groupsList}) + 50, q->minimumSizeHint().height()});
    }

private:
    std::vector<Key> selectedKeys;
    std::vector<Key> unselectedKeys;
    struct UI {
        QLabel selectedLB;
        QListWidget *selectedList;
        QLabel unselectedLB;
        QListWidget *unselectedList;
        QLabel groupsLB;
        QListWidget *groupsList;
        QDialogButtonBox buttonBox;
        QVBoxLayout vlay;

        explicit UI(DeleteCertificatesDialog *qq)
            : selectedLB({}, qq)
            , selectedList(new QListWidget)
            , unselectedLB({}, qq)
            , unselectedList(new QListWidget)
            , groupsLB({}, qq)
            , groupsList(new QListWidget)
            , buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel)
            , vlay(qq)
        {
            Q_SET_OBJECT_NAME(selectedLB);
            Q_SET_OBJECT_NAME(selectedList);
            Q_SET_OBJECT_NAME(unselectedLB);
            Q_SET_OBJECT_NAME(unselectedList);
            Q_SET_OBJECT_NAME(groupsLB);
            Q_SET_OBJECT_NAME(groupsList);
            Q_SET_OBJECT_NAME(buttonBox);
            Q_SET_OBJECT_NAME(vlay);

            selectedList->setAccessibleName(i18nc("@label", "Certificates"));
            unselectedList->setAccessibleName(i18nc("@label", "Certificates"));
            groupsList->setAccessibleName(i18nc("@label", "Groups"));

            vlay.addWidget(&selectedLB);
            vlay.addWidget(selectedList, 1);
            vlay.addWidget(&unselectedLB);
            vlay.addWidget(unselectedList, 1);
            vlay.addWidget(&groupsLB);
            vlay.addWidget(groupsList, 1);
            vlay.addWidget(&buttonBox);

            unselectedLB.setContextMenuPolicy(Qt::NoContextMenu);

            buttonBox.button(QDialogButtonBox::Ok)->setText(i18nc("@action:button", "Delete"));

            connect(&unselectedLB, &QLabel::linkActivated, qq, [qq]() {
                KMessageBox::information(qq,
                                         xi18nc("@info",
                                                "<para>When you delete CA certificates (both root CAs and intermediate CAs), "
                                                "the certificates issued by them will also be deleted.</para>"
                                                "<para>This can be nicely seen in <application>Kleopatra</application>'s "
                                                "hierarchical view mode: In this mode, if you delete a certificate that has "
                                                "children, those children will also be deleted. Think of CA certificates as "
                                                "folders containing other certificates: When you delete the folder, you "
                                                "delete its contents, too.</para>"));
            });

            groupsLB.setVisible(false);
            unselectedList->setVisible(false);
            groupsList->setVisible(false);

            connect(&buttonBox, SIGNAL(accepted()), qq, SLOT(accept()));
            connect(&buttonBox, &QDialogButtonBox::rejected, qq, &QDialog::reject);
        }
    } ui;
};

DeleteCertificatesDialog::DeleteCertificatesDialog(QWidget *p)
    : QDialog(p)
    , d(new Private(this))
{
    d->readConfig();
}

DeleteCertificatesDialog::~DeleteCertificatesDialog()
{
    d->writeConfig();
}

void DeleteCertificatesDialog::setSelectedKeys(const std::vector<Key> &keys)
{
    d->selectedKeys = keys;
    for (const auto &key : keys) {
        d->ui.selectedList->addItem(Formatting::summaryLine(key));
    }
    d->ui.selectedLB.setText(
        i18np("The following certificate was selected for deletion:", "The following certificates were selected for deletion:", keys.size()));
    d->checkGroups(keys);
}

void DeleteCertificatesDialog::setUnselectedKeys(const std::vector<Key> &keys)
{
    d->unselectedKeys = keys;
    d->ui.unselectedLB.setVisible(!keys.empty());
    for (const auto &key : keys) {
        d->ui.unselectedList->addItem(Formatting::summaryLine(key));
    }
    d->ui.unselectedList->setVisible(d->ui.unselectedList->count() > 0);
    d->ui.unselectedLB.setText(
        i18np("The following certificate will be deleted even though you did <b>not</b> "
              "explicitly select it (<a href=\"whatsthis://\">Why?</a>):",
              "The following certificates will be deleted even though you did <b>not</b> "
              "explicitly select them (<a href=\"whatsthis://\">Why?</a>):",
              keys.size()));
    d->checkGroups(keys);
}

std::vector<Key> DeleteCertificatesDialog::keys() const
{
    const std::vector<Key> sel = d->selectedKeys;
    const std::vector<Key> uns = d->unselectedKeys;
    std::vector<Key> result;
    result.reserve(sel.size() + uns.size());
    result.insert(result.end(), sel.begin(), sel.end());
    result.insert(result.end(), uns.begin(), uns.end());
    return result;
}

void DeleteCertificatesDialog::accept()
{
    const std::vector<Key> sel = d->selectedKeys;
    const std::vector<Key> uns = d->unselectedKeys;

    const uint secret =
        std::count_if(sel.cbegin(), sel.cend(), std::mem_fn(&Key::hasSecret)) + std::count_if(uns.cbegin(), uns.cend(), std::mem_fn(&Key::hasSecret));
    const uint total = sel.size() + uns.size();

    int ret = KMessageBox::Continue;
    if (secret)
        ret = KMessageBox::warningContinueCancel(this,
                                                 secret == total ? i18np("The certificate to be deleted is your own. "
                                                                         "It contains private key material, "
                                                                         "which is needed to decrypt past communication "
                                                                         "encrypted to the certificate, and should therefore "
                                                                         "not be deleted.",

                                                                         "All of the certificates to be deleted "
                                                                         "are your own. "
                                                                         "They contain private key material, "
                                                                         "which is needed to decrypt past communication "
                                                                         "encrypted to the certificate, and should therefore "
                                                                         "not be deleted.",

                                                                         secret)
                                                                 : i18np("One of the certificates to be deleted "
                                                                         "is your own. "
                                                                         "It contains private key material, "
                                                                         "which is needed to decrypt past communication "
                                                                         "encrypted to the certificate, and should therefore "
                                                                         "not be deleted.",

                                                                         "Some of the certificates to be deleted "
                                                                         "are your own. "
                                                                         "They contain private key material, "
                                                                         "which is needed to decrypt past communication "
                                                                         "encrypted to the certificate, and should therefore "
                                                                         "not be deleted.",

                                                                         secret),
                                                 i18nc("@title:window", "Secret Key Deletion"),
                                                 KStandardGuiItem::guiItem(KStandardGuiItem::Delete),
                                                 KStandardGuiItem::cancel(),
                                                 QString(),
                                                 KMessageBox::Notify | KMessageBox::Dangerous);

    if (ret == KMessageBox::Continue) {
        QDialog::accept();
    } else {
        QDialog::reject();
    }
}

#include "moc_deletecertificatesdialog.cpp"
