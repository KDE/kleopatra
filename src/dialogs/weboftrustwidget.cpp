/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "weboftrustwidget.h"

#include "commands/certifycertificatecommand.h"
#include "commands/importcertificatefromkeyservercommand.h"
#include "commands/revokecertificationcommand.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/TreeView>
#include <Libkleo/UserIDListModel>
#include <Libkleo/UserIDListProxyModel>

#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QVBoxLayout>

#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

#include "kleopatra_debug.h"

using namespace Kleo;

namespace
{
void addActionButton(QLayout *buttonBox, QAction *action)
{
    if (!action) {
        return;
    }
    auto button = new QPushButton(buttonBox->parentWidget());
    button->setText(action->text());
    buttonBox->addWidget(button);
    button->setEnabled(action->isEnabled());
    QObject::connect(action, &QAction::changed, button, [action, button]() {
        button->setEnabled(action->isEnabled());
    });
    QObject::connect(button, &QPushButton::clicked, action, &QAction::trigger);
}
}

class WebOfTrustWidget::Private
{
    friend class ::Kleo::WebOfTrustWidget;
    WebOfTrustWidget *const q;

private:
    GpgME::Key key;
    UserIDListModel certificationsModel;
    UserIDListProxyModel proxyModel;
    QGpgME::KeyListJob *keyListJob = nullptr;
    TreeView *certificationsTV = nullptr;
    QAction *detailsAction = nullptr;
    QAction *certifyAction = nullptr;
    QAction *revokeAction = nullptr;
    QAction *fetchAction = nullptr;
    QLabel *notAvailableLabel = nullptr;
    QPushButton *moreButton = nullptr;
    QCheckBox *showOnlyOwnCheck = nullptr;

public:
    Private(WebOfTrustWidget *qq)
        : q{qq}
    {
        certificationsModel.enableRemarks(true);
        auto vLay = new QVBoxLayout(q);
        vLay->setContentsMargins({});

        proxyModel.setSourceModel(&certificationsModel);

        certificationsTV = new TreeView{q};
        certificationsTV->setAccessibleName(i18n("User IDs and certifications"));
        certificationsTV->setModel(&proxyModel);
        certificationsTV->setAllColumnsShowFocus(false);
        certificationsTV->setSelectionMode(QAbstractItemView::SingleSelection);
        vLay->addWidget(certificationsTV);

        notAvailableLabel = new QLabel(i18nc("@info", "Certifications are not available before the certificate is imported."));
        notAvailableLabel->setAlignment(Qt::AlignHCenter);
        notAvailableLabel->setVisible(false);
        vLay->addWidget(notAvailableLabel);

        detailsAction = new QAction{QIcon::fromTheme(QStringLiteral("dialog-information")), i18nc("@action", "Show Certificate Details"), q};
        connect(detailsAction, &QAction::triggered, q, [this]() {
            showCertificateDetails();
        });

        certifyAction = new QAction{QIcon::fromTheme(QStringLiteral("view-certificate-sign")), i18nc("@action", "Add Certification"), q};
        connect(certifyAction, &QAction::triggered, q, [this]() {
            addCertification();
        });

        if (Kleo::Commands::RevokeCertificationCommand::isSupported()) {
            revokeAction = new QAction{QIcon::fromTheme(QStringLiteral("view-certificate-revoke")), i18nc("@action", "Revoke Certification"), q};
            connect(revokeAction, &QAction::triggered, q, [this]() {
                revokeCertification();
            });
        }

        fetchAction = new QAction(QIcon::fromTheme(QStringLiteral("download")), i18nc("@action:button", "Fetch Missing Keys"));
        fetchAction->setToolTip(i18nc("@info:tooltip", "Look up and import all keys that were used to certify the user IDs of this key"));
        connect(fetchAction, &QAction::triggered, q, [this]() {
            fetchMissingKeys();
        });

        auto bbox = new QHBoxLayout;

        addActionButton(bbox, certifyAction);
        addActionButton(bbox, revokeAction);

        moreButton = new QPushButton(QIcon::fromTheme(QStringLiteral("application-menu")), {});
        moreButton->setToolTip(i18nc("@info:tooltip", "Show more options"));
        bbox->addWidget(moreButton);
        connect(moreButton, &QPushButton::clicked, q, [this]() {
            auto menu = new QMenu(q);
            menu->addAction(detailsAction);
            menu->addAction(fetchAction);
            menu->popup(moreButton->mapToGlobal(QPoint()));
        });

        showOnlyOwnCheck = new QCheckBox(i18nc("label:checkbox", "Show only my own certifications"));
        bbox->addWidget(showOnlyOwnCheck);
        connect(showOnlyOwnCheck, &QCheckBox::toggled, &proxyModel, &UserIDListProxyModel::setShowOnlyOwnCertifications);

        bbox->addStretch(1);

        vLay->addLayout(bbox);

        connect(certificationsTV, &QAbstractItemView::doubleClicked, q, [this]() {
            certificationDblClicked();
        });
        certificationsTV->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(certificationsTV, &QWidget::customContextMenuRequested, q, [this](const QPoint &p) {
            contextMenuRequested(p);
        });
        connect(certificationsTV->selectionModel(), &QItemSelectionModel::currentRowChanged, q, [this]() {
            updateActions();
        });
        updateActions();
    }

    GpgME::UserID selectedUserID()
    {
        return proxyModel.userID(certificationsTV->currentIndex());
    }

    GpgME::UserID::Signature selectedCertification()
    {
        return proxyModel.signature(certificationsTV->currentIndex());
    }

    void certificationDblClicked()
    {
        showCertificateDetails();
    }

    void showCertificateDetails()
    {
        const auto signature = selectedCertification();
        if (signature.isNull()) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "- no certification selected";
            return;
        }
        auto cmd = Command::commandForQuery(QString::fromUtf8(signature.signerKeyID()));
        cmd->setParentWidget(q->window());
        cmd->start();
    }

    void addCertification()
    {
        auto userID = selectedUserID();
        if (userID.isNull()) {
            userID = selectedCertification().parent();
        }
        if (userID.isNull()) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "- no user ID or certification selected";
            return;
        }
        auto cmd = new Kleo::Commands::CertifyCertificateCommand(userID);
        cmd->setParentWidget(q);
        certificationsTV->setEnabled(false);
        connect(cmd, &Kleo::Commands::CertifyCertificateCommand::finished, q, [this]() {
            certificationsTV->setEnabled(true);
            // Trigger an update when done
            q->setKey(key);
        });
        cmd->start();
    }

    void revokeCertification()
    {
        Command *cmd = nullptr;
        if (const auto signature = selectedCertification(); !signature.isNull()) {
            cmd = new Kleo::Commands::RevokeCertificationCommand(signature);
        } else if (const auto userID = selectedUserID(); !userID.isNull()) {
            cmd = new Kleo::Commands::RevokeCertificationCommand(userID);
        } else {
            qCDebug(KLEOPATRA_LOG) << __func__ << "- no user ID or certification selected";
            return;
        }
        cmd->setParentWidget(q);
        certificationsTV->setEnabled(false);
        connect(cmd, &Kleo::Commands::RevokeCertificationCommand::finished, q, [this]() {
            certificationsTV->setEnabled(true);
            // Trigger an update when done
            q->setKey(key);
        });
        cmd->start();
    }

    void addActionsForUserID(QMenu *menu)
    {
        menu->addAction(certifyAction);
        if (revokeAction) {
            menu->addAction(revokeAction);
        }
    }

    void addActionsForSignature(QMenu *menu)
    {
        menu->addAction(detailsAction);
        if (revokeAction) {
            menu->addAction(revokeAction);
            if (!revokeAction->isEnabled()) {
                menu->setToolTipsVisible(true);
            }
        }
    }

    void updateActions()
    {
        const auto userCanSignUserIDs = userHasCertificationKey();
        const auto keyCanBeCertified = Kleo::canBeCertified(key);
        const auto userID = selectedUserID();
        const auto signature = selectedCertification();
        detailsAction->setEnabled(!signature.isNull());
        certifyAction->setEnabled(keyCanBeCertified && userCanSignUserIDs && !userID.isNull());
        if (revokeAction) {
            revokeAction->setToolTip({});
            if (!signature.isNull()) {
                const auto revocationFeasibility = userCanRevokeCertification(signature);
                revokeAction->setEnabled(revocationFeasibility == CertificationCanBeRevoked);
                switch (revocationFeasibility) {
                case CertificationCanBeRevoked:
                    break;
                case CertificationNotMadeWithOwnKey:
                    revokeAction->setToolTip(
                        i18n("You cannot revoke this certification because it wasn't made with one of your keys (or the required secret key is missing)."));
                    break;
                case CertificationIsSelfSignature:
                    revokeAction->setToolTip(i18nc("@info:tooltip", "Revocation of self-certifications is currently not possible."));
                    break;
                case CertificationIsRevocation:
                    revokeAction->setToolTip(
                        i18nc("@info:tooltip", "You cannot revoke this revocation certification. (But you can re-certify the corresponding user ID.)"));
                    break;
                case CertificationIsExpired:
                    revokeAction->setToolTip(i18nc("@info:tooltip", "You cannot revoke this expired certification."));
                    break;
                case CertificationIsInvalid:
                    revokeAction->setToolTip(i18nc("@info:tooltip", "You cannot revoke this invalid certification."));
                    break;
                case CertificationKeyNotAvailable:
                    revokeAction->setToolTip(i18nc("@info:tooltip", "You cannot revoke this certification because the required secret key is not available."));
                    break;
                };
            } else if (!userID.isNull()) {
                const bool canRevokeCertification = userCanRevokeCertifications(userID);
                revokeAction->setEnabled(canRevokeCertification);
                if (!canRevokeCertification) {
                    revokeAction->setToolTip(
                        i18n("You cannot revoke any of the certifications of this user ID. Select any of the certifications for details."));
                }
            } else {
                revokeAction->setEnabled(false);
            }
        }
    }

    void contextMenuRequested(const QPoint &p)
    {
        const auto userID = proxyModel.userID(certificationsTV->indexAt(p));
        const auto signature = proxyModel.signature(certificationsTV->indexAt(p));

        if (userID.isNull() && signature.isNull()) {
            return;
        }

        auto menu = new QMenu(q);
        if (!userID.isNull()) {
            addActionsForUserID(menu);
        } else if (!signature.isNull()) {
            addActionsForSignature(menu);
        }
        connect(menu, &QMenu::aboutToHide, menu, &QObject::deleteLater);
        menu->popup(certificationsTV->viewport()->mapToGlobal(p));
    }

    void startSignatureListing()
    {
        if (keyListJob) {
            return;
        }
        QGpgME::KeyListJob *const job = QGpgME::openpgp()->keyListJob(/*remote*/ false, /*includeSigs*/ true, /*validate*/ true);
        if (!job) {
            return;
        }

        job->addMode(GpgME::SignatureNotations);

        connect(job, &QGpgME::KeyListJob::result, q, &WebOfTrustWidget::signatureListingDone);

        connect(job, &QGpgME::KeyListJob::nextKey, q, &WebOfTrustWidget::signatureListingNextKey);

        job->start(QStringList(QString::fromLatin1(key.primaryFingerprint())));
        keyListJob = job;
    }

    void fetchMissingKeys()
    {
        if (q->key().isNull()) {
            return;
        }
        const auto missingSignerKeyIds = Kleo::getMissingSignerKeyIds(q->key().userIDs());

        auto cmd = new Kleo::ImportCertificateFromKeyserverCommand{QStringList{std::begin(missingSignerKeyIds), std::end(missingSignerKeyIds)}};
        cmd->setParentWidget(q);
        fetchAction->setEnabled(false);
        connect(cmd, &Kleo::ImportCertificateFromKeyserverCommand::finished, q, [this]() {
            // Trigger an update when done
            q->setKey(q->key());
            fetchAction->setEnabled(true);
        });
        cmd->start();
    }
};

WebOfTrustWidget::WebOfTrustWidget(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
}

WebOfTrustWidget::~WebOfTrustWidget() = default;

QAction *WebOfTrustWidget::detailsAction() const
{
    return d->detailsAction;
}

QAction *WebOfTrustWidget::certifyAction() const
{
    return d->certifyAction;
}

QAction *WebOfTrustWidget::revokeAction() const
{
    return d->revokeAction;
}

GpgME::Key WebOfTrustWidget::key() const
{
    return d->key;
}

void WebOfTrustWidget::setKey(const GpgME::Key &key)
{
    if (key.protocol() != GpgME::OpenPGP) {
        qCDebug(KLEOPATRA_LOG) << "List of Certifications is only supported for OpenPGP keys";
        return;
    }

    if (isRemoteKey(key)) {
        d->certificationsTV->setVisible(false);
        d->notAvailableLabel->setVisible(true);
        d->moreButton->setEnabled(false);
    }

    d->key = key;
    d->certificationsModel.setKey(key);
    d->updateActions();
    d->certificationsTV->expandAll();
    d->startSignatureListing();
    if (!d->certificationsTV->restoreColumnLayout(QStringLiteral("WebOfTrustWidget"))) {
        d->certificationsTV->resizeToContentsLimited();
    }
    d->fetchAction->setEnabled(!key.isBad());
}

void WebOfTrustWidget::signatureListingNextKey(const GpgME::Key &key)
{
    GpgME::Key merged = key;
    merged.mergeWith(d->key);
    setKey(merged);
}

void WebOfTrustWidget::signatureListingDone(const GpgME::KeyListResult &result)
{
    if (result.error()) {
        KMessageBox::information(this,
                                 xi18nc("@info",
                                        "<para>An error occurred while loading the certifications: "
                                        "<message>%1</message></para>",
                                        Formatting::errorAsString(result.error())),
                                 i18nc("@title", "Certifications Loading Failed"));
    }
    d->keyListJob = nullptr;
}

#include "moc_weboftrustwidget.cpp"
