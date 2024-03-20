/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/deletecertificatesdialog.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "deletecertificatesdialog.h"

#include <utils/accessibility.h>
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
#include <QPushButton>
#include <QTreeView>
#include <QVBoxLayout>
#include <QWhatsThis>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace GpgME;

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

    void slotWhatsThisRequested()
    {
        qCDebug(KLEOPATRA_LOG);
        if (QWidget *const widget = qobject_cast<QWidget *>(q->sender()))
            if (!widget->whatsThis().isEmpty()) {
                showToolTip(QCursor::pos(), widget->whatsThis(), widget);
            }
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
        const auto &groups = KeyCache::instance()->groups();
        for (const auto &key : keys) {
            QStringList foundGroups;
            if (Kleo::any_of(groups, [key, &foundGroups](const auto &group) {
                    if (group.keys().contains(key)) {
                        foundGroups.append(group.name());
                        return true;
                    }
                    return false;
                })) {
                ui.groupsList->addWidget(
                    new QLabel(i18nc("<certificate name>, contained in: (list of groups)", "\t• %1, contained in:").arg(Formatting::prettyNameAndEMail(key))));
                for (const auto &group : foundGroups) {
                    ui.groupsList->addWidget(new QLabel(QStringLiteral("\t\t• %1").arg(group)));
                }
                keyInGroups++;
                ui.groupsLB.setVisible(true);
            }
        }
        ui.groupsLB.setText(
            i18np("The following certificate is part of at least one group. Deleting it may cause receivers to be unable to decrypt messages:",
                  "The following certificates are part of at least one group. Deleting them may cause receivers to be unable to decrypt messages:",
                  keyInGroups));
    }

private:
    std::vector<Key> selectedKeys;
    std::vector<Key> unselectedKeys;
    int keyInGroups = 0;
    struct UI {
        QLabel selectedLB;
        QVBoxLayout *selectedList;
        QLabel unselectedLB;
        QVBoxLayout *unselectedList;
        QLabel groupsLB;
        QVBoxLayout *groupsList;
        QDialogButtonBox buttonBox;
        QVBoxLayout vlay;

        explicit UI(DeleteCertificatesDialog *qq)
            : selectedLB({}, qq)
            , unselectedLB({}, qq)
            , groupsLB({}, qq)
            , buttonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel)
            , vlay(qq)
            , selectedList(new QVBoxLayout)
            , unselectedList(new QVBoxLayout)
            , groupsList(new QVBoxLayout)
        {
            KDAB_SET_OBJECT_NAME(selectedLB);
            KDAB_SET_OBJECT_NAME(selectedList);
            KDAB_SET_OBJECT_NAME(unselectedLB);
            KDAB_SET_OBJECT_NAME(unselectedList);
            KDAB_SET_OBJECT_NAME(groupsLB);
            KDAB_SET_OBJECT_NAME(groupsList);
            KDAB_SET_OBJECT_NAME(buttonBox);
            KDAB_SET_OBJECT_NAME(vlay);

            vlay.addWidget(&selectedLB);
            vlay.addLayout(selectedList, 0);
            vlay.addWidget(&unselectedLB);
            vlay.addLayout(unselectedList, 0);
            vlay.addWidget(&groupsLB);
            vlay.addLayout(groupsList, 0);
            vlay.addWidget(&buttonBox);

            const QString unselectedWhatsThis = xi18nc("@info:whatsthis",
                                                       "<title>Why do you want to delete more certificates than I selected?</title>"
                                                       "<para>When you delete CA certificates (both root CAs and intermediate CAs), "
                                                       "the certificates issued by them will also be deleted.</para>"
                                                       "<para>This can be nicely seen in <application>Kleopatra</application>'s "
                                                       "hierarchical view mode: In this mode, if you delete a certificate that has "
                                                       "children, those children will also be deleted. Think of CA certificates as "
                                                       "folders containing other certificates: When you delete the folder, you "
                                                       "delete its contents, too.</para>");
            unselectedLB.setContextMenuPolicy(Qt::NoContextMenu);
            unselectedLB.setWhatsThis(unselectedWhatsThis);

            buttonBox.button(QDialogButtonBox::Ok)->setText(i18nc("@action:button", "Delete"));

            connect(&unselectedLB, SIGNAL(linkActivated(QString)), qq, SLOT(slotWhatsThisRequested()));

            groupsLB.setVisible(false);

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
        d->ui.selectedList->addWidget(new QLabel(QStringLiteral("\t• %1").arg(Formatting::prettyNameAndEMail(key))));
    }
    d->ui.selectedLB.setText(
        i18np("The following certificate was selected for deletion:", "The following certificates were selected for deletion:", keys.size()));
    d->checkGroups(keys);
    resize(sizeHint());
}

void DeleteCertificatesDialog::setUnselectedKeys(const std::vector<Key> &keys)
{
    d->unselectedKeys = keys;
    d->ui.unselectedLB.setVisible(!keys.empty());
    for (const auto &key : keys) {
        d->ui.unselectedList->addWidget(new QLabel(QStringLiteral("\t• %1").arg(Formatting::prettyNameAndEMail(key))));
    }
    d->ui.unselectedLB.setText(
        i18np("The following certificate will be deleted even though you did <b>not</b> "
              "explicitly select it (<a href=\"whatsthis://\">Why?</a>):",
              "The following certificates will be deleted even though you did <b>not</b> "
              "explicitly select them (<a href=\"whatsthis://\">Why?</a>):",
              keys.size()));
    d->checkGroups(keys);
    resize(sizeHint());
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
