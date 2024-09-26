/* -*- mode: c++; c-basic-offset:4 -*-
    view/keylistcontroller.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 Felix Tiede

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "keylistcontroller.h"
#include "tabwidget.h"

#include <smartcard/readerstatus.h>

#include <utils/action_data.h>

#include "commands/exportcertificatecommand.h"
#include "commands/exportopenpgpcertstoservercommand.h"
#include "kleopatra_debug.h"
#include "tooltippreferences.h"
#include <settings.h>
#ifdef MAILAKONADI_ENABLED
#include "commands/exportopenpgpcerttoprovidercommand.h"
#endif // MAILAKONADI_ENABLED
#include "commands/adduseridcommand.h"
#include "commands/certificatetocardcommand.h"
#include "commands/certifycertificatecommand.h"
#include "commands/changeexpirycommand.h"
#include "commands/changeownertrustcommand.h"
#include "commands/changepassphrasecommand.h"
#include "commands/changeroottrustcommand.h"
#include "commands/checksumcreatefilescommand.h"
#include "commands/checksumverifyfilescommand.h"
#include "commands/clearcrlcachecommand.h"
#include "commands/creategroupcommand.h"
#include "commands/decryptverifyfilescommand.h"
#include "commands/deletecertificatescommand.h"
#include "commands/detailscommand.h"
#include "commands/dumpcertificatecommand.h"
#include "commands/dumpcrlcachecommand.h"
#include "commands/exportpaperkeycommand.h"
#include "commands/exportsecretkeycommand.h"
#include "commands/importcertificatefromfilecommand.h"
#include "commands/importcrlcommand.h"
#include "commands/lookupcertificatescommand.h"
#include "commands/newcertificatesigningrequestcommand.h"
#include "commands/newopenpgpcertificatecommand.h"
#include "commands/refreshcertificatescommand.h"
#include "commands/refreshopenpgpcertscommand.h"
#include "commands/refreshx509certscommand.h"
#include "commands/reloadkeyscommand.h"
#include "commands/revokecertificationcommand.h"
#include "commands/revokekeycommand.h"
#include "commands/signencryptfilescommand.h"
#include "commands/signencryptfoldercommand.h"
#include "commands/togglecertificateenabledcommand.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyListModel>

#include <gpgme++/key.h>

#include <gpgme.h>

#include <KActionCollection>
#include <KLocalizedString>

#include <QAbstractItemView>
#include <QAction>
#include <QClipboard>
#include <QGuiApplication>
#include <QItemSelectionModel>
#include <QPointer>

#include <algorithm>
#include <iterator>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;

namespace ranges = std::ranges;

class KeyListController::Private
{
    friend class ::Kleo::KeyListController;
    KeyListController *const q;

public:
    explicit Private(KeyListController *qq);
    ~Private();

    void connectView(QAbstractItemView *view);
    void connectCommand(Command *cmd);

    void connectTabWidget();
    void disconnectTabWidget();

    void addCommand(Command *cmd)
    {
        connectCommand(cmd);
        commands.insert(ranges::lower_bound(commands, cmd), cmd);
    }
    void addView(QAbstractItemView *view)
    {
        connectView(view);
        views.insert(ranges::lower_bound(views, view), view);
    }
    void removeView(QAbstractItemView *view)
    {
        view->disconnect(q);
        view->selectionModel()->disconnect(q);
        std::erase(views, view);
    }

public:
    void slotDestroyed(QObject *o)
    {
        qCDebug(KLEOPATRA_LOG) << (void *)o;
        std::erase(views, o);
        std::erase(commands, o);
    }
    void slotDoubleClicked(const QModelIndex &idx);
    void slotActivated(const QModelIndex &idx);
    void slotSelectionChanged(const QItemSelection &old, const QItemSelection &new_);
    void slotContextMenu(const QPoint &pos);
    void slotCommandFinished();
    void slotActionTriggered(QAction *action);
    void slotCurrentViewChanged(QAbstractItemView *view)
    {
        if (view && !ranges::binary_search(views, view)) {
            qCDebug(KLEOPATRA_LOG) << "you need to register view" << view << "before trying to set it as the current view!";
            addView(view);
        }
        currentView = view;
        q->enableDisableActions(view ? view->selectionModel() : nullptr);
    }
    void updateActions(KActionCollection *collection);

private:
    int toolTipOptions() const;

private:
    static Command::Restrictions calculateRestrictionsMask(const QItemSelectionModel *sm);

private:
    struct action_item {
        QPointer<QAction> action;
        Command::Restrictions restrictions;
        Command *(*createCommand)(QAbstractItemView *, KeyListController *);
    };
    std::vector<action_item> actions;
    std::vector<QAbstractItemView *> views;
    std::vector<Command *> commands;
    QPointer<QWidget> parentWidget;
    QPointer<TabWidget> tabWidget;
    QPointer<QAbstractItemView> currentView;
    QPointer<AbstractKeyListModel> flatModel, hierarchicalModel;
    std::vector<QMetaObject::Connection> m_connections;
};

KeyListController::Private::Private(KeyListController *qq)
    : q(qq)
    , actions()
    , views()
    , commands()
    , parentWidget()
    , tabWidget()
    , flatModel()
    , hierarchicalModel()
{
}

KeyListController::Private::~Private()
{
}

KeyListController::KeyListController(QObject *p)
    : QObject(p)
    , d(new Private(this))
{
}

KeyListController::~KeyListController()
{
}

void KeyListController::addView(QAbstractItemView *view)
{
    if (!view || ranges::binary_search(d->views, view)) {
        return;
    }
    d->addView(view);
}

void KeyListController::removeView(QAbstractItemView *view)
{
    if (!view || !ranges::binary_search(d->views, view)) {
        return;
    }
    d->removeView(view);
}

void KeyListController::setCurrentView(QAbstractItemView *view)
{
    d->slotCurrentViewChanged(view);
}

std::vector<QAbstractItemView *> KeyListController::views() const
{
    return d->views;
}

void KeyListController::setFlatModel(AbstractKeyListModel *model)
{
    if (model == d->flatModel) {
        return;
    }

    d->flatModel = model;

    if (model) {
        model->setToolTipOptions(d->toolTipOptions());
    }
}

void KeyListController::setHierarchicalModel(AbstractKeyListModel *model)
{
    if (model == d->hierarchicalModel) {
        return;
    }

    d->hierarchicalModel = model;

    if (model) {
        model->setToolTipOptions(d->toolTipOptions());
    }
}

void KeyListController::setTabWidget(TabWidget *tabWidget)
{
    if (tabWidget == d->tabWidget) {
        return;
    }

    d->disconnectTabWidget();

    d->tabWidget = tabWidget;

    d->connectTabWidget();

    d->slotCurrentViewChanged(tabWidget ? tabWidget->currentView() : nullptr);
}

void KeyListController::setParentWidget(QWidget *parent)
{
    d->parentWidget = parent;
}

QWidget *KeyListController::parentWidget() const
{
    return d->parentWidget;
}

void KeyListController::Private::connectTabWidget()
{
    if (!tabWidget) {
        return;
    }
    const auto views = tabWidget->views();
    ranges::for_each(views, [this](QAbstractItemView *view) {
        addView(view);
    });

    m_connections.reserve(3);
    m_connections.push_back(connect(tabWidget, &TabWidget::viewAdded, q, &KeyListController::addView));
    m_connections.push_back(connect(tabWidget, &TabWidget::viewAboutToBeRemoved, q, &KeyListController::removeView));
    m_connections.push_back(connect(tabWidget, &TabWidget::currentViewChanged, q, [this](QAbstractItemView *view) {
        slotCurrentViewChanged(view);
    }));
}

void KeyListController::Private::disconnectTabWidget()
{
    if (!tabWidget) {
        return;
    }
    for (const auto &connection : m_connections) {
        disconnect(connection);
    }
    m_connections.clear();

    const auto views = tabWidget->views();
    ranges::for_each(views, [this](QAbstractItemView *view) {
        removeView(view);
    });
}

AbstractKeyListModel *KeyListController::flatModel() const
{
    return d->flatModel;
}

AbstractKeyListModel *KeyListController::hierarchicalModel() const
{
    return d->hierarchicalModel;
}

QAbstractItemView *KeyListController::currentView() const
{
    return d->currentView;
}

TabWidget *KeyListController::tabWidget() const
{
    return d->tabWidget;
}

void KeyListController::createActions(KActionCollection *coll)
{
    std::vector<action_data> common_and_openpgp_action_data = {
        // File menu
        {
            "file_new_certificate",
            i18n("New OpenPGP Key Pair..."),
            i18n("Create a new OpenPGP certificate"),
            "view-certificate-add",
            nullptr,
            nullptr,
            QStringLiteral("Ctrl+N"),
        },
        {
            "file_export_certificates",
            i18n("Export..."),
            i18n("Export the selected certificate (public key) to a file"),
            "view-certificate-export",
            nullptr,
            nullptr,
            QStringLiteral("Ctrl+E"),
        },
        {
            "file_export_certificates_to_server",
            i18n("Publish on Server..."),
            keyserver().startsWith(QStringLiteral("ldap:")) || keyserver().startsWith(QStringLiteral("ldaps:"))
                ? i18n("Publish the selected certificate (public key) to internal directory")
                : i18n("Publish the selected certificate (public key) on %1", keyserver()),
            "view-certificate-export-server",
            nullptr,
            nullptr,
            QStringLiteral("Ctrl+Shift+E"),
        },
#ifdef MAILAKONADI_ENABLED
        {
            "file_export_certificate_to_provider",
            i18n("Publish at Mail Provider..."),
            i18n("Publish the selected certificate (public key) at mail provider's Web Key Directory if offered"),
            "view-certificate-export",
            nullptr,
            nullptr,
            QString(),
        },
#endif // MAILAKONADI_ENABLED
        {
            "file_export_secret_keys",
            i18n("Backup Secret Keys..."),
            QString(),
            "view-certificate-export-secret",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "file_export_paper_key",
            i18n("Print Secret Key..."),
            QString(),
            "document-print",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "file_lookup_certificates",
            i18n("Lookup on Server..."),
            keyserver().startsWith(QStringLiteral("ldap:")) || keyserver().startsWith(QStringLiteral("ldaps:"))
                ? i18n("Search for certificates in internal directory")
                : i18n("Search for certificates on %1", keyserver()),
            "edit-find",
            nullptr,
            nullptr,
            QStringLiteral("Shift+Ctrl+I"),
        },
        {
            "file_import_certificates",
            i18n("Import..."),
            i18n("Import a certificate from a file"),
            "view-certificate-import",
            nullptr,
            nullptr,
            QStringLiteral("Ctrl+I"),
        },
        {
            "file_decrypt_verify_files",
            i18n("Decrypt/Verify..."),
            i18n("Decrypt and/or verify files"),
            "document-edit-decrypt-verify",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "file_sign_encrypt_files",
            i18n("Sign/Encrypt..."),
            i18n("Encrypt and/or sign files"),
            "document-edit-sign-encrypt",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "file_sign_encrypt_folder",
            i18n("Sign/Encrypt Folder..."),
            i18n("Encrypt and/or sign folders"),
            "folder-edit-sign-encrypt-symbolic",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "file_checksum_create_files",
            i18n("Create Checksum Files..."),
            QString(),
            nullptr /*"document-checksum-create"*/,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "file_checksum_verify_files",
            i18n("Verify Checksum Files..."),
            QString(),
            nullptr /*"document-checksum-verify"*/,
            nullptr,
            nullptr,
            QString(),
        },
        // View menu
        {
            "view_redisplay",
            i18n("Redisplay"),
            QString(),
            "view-refresh",
            nullptr,
            nullptr,
            QStringLiteral("F5"),
        },
        {
            "view_stop_operations",
            i18n("Stop Operation"),
            QString(),
            "process-stop",
            this,
            [this](bool) {
                cancelCommands();
            },
            QStringLiteral("Escape"),
            RegularQAction,
            Disabled,
        },
        {
            "view_certificate_details",
            i18n("Details"),
            QString(),
            "dialog-information",
            nullptr,
            nullptr,
            QString(),
        },
        // Certificate menu
        {
            "certificates_revoke",
            i18n("Revoke Certificate..."),
            i18n("Revoke the selected OpenPGP certificate"),
            "view-certificate-revoke",
            nullptr,
            nullptr,
            {},
        },
        {
            "certificates_delete",
            i18n("Delete"),
            i18n("Delete selected certificates"),
            "edit-delete",
            nullptr,
            nullptr,
            QStringLiteral("Delete"),
        },
        {
            "certificates_refresh",
            i18n("Update Certificates"),
            i18n("Update selected certificates"),
            "view-refresh",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_certify_certificate",
            i18n("Certify..."),
            i18n("Certify the validity of the selected certificate"),
            "view-certificate-sign",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_revoke_certification",
            i18n("Revoke Certification..."),
            i18n("Revoke the certification of the selected certificate"),
            "view-certificate-revoke",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_change_expiry",
            i18n("Change End of Validity Period..."),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_change_owner_trust",
            i18nc("@action:inmenu", "Change Certification Power..."),
            i18nc("@info:tooltip", "Grant or revoke the certification power of the selected certificate"),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_change_passphrase",
            i18n("Change Passphrase..."),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_add_userid",
            i18n("Add User ID..."),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_create_group",
            i18nc("@action:inmenu", "Create Group..."),
            i18nc("@info:tooltip", "Create a group from the selected certificates"),
            "resource-group-new",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificate_to_card",
            i18nc("@action:inmenu", "Copy to Card"),
            i18nc("@info:tooltip", "Copy the selected certificate to a smartcard"),
            "auth-sim-locked",
            nullptr,
            nullptr,
            QString(),
        },
        // Tools menu
        {
            "tools_refresh_openpgp_certificates",
            i18n("Refresh OpenPGP Certificates"),
            QString(),
            "view-refresh",
            nullptr,
            nullptr,
            QString(),
        },
        // Context Menu
        {
            "cell_copy",
            i18nc("@action:button", "Copy"),
            QString(),
            "edit-copy",
            this,
            [this](bool) {
                QGuiApplication::clipboard()->setText(currentView()->currentIndex().data(Kleo::ClipboardRole).toString());
            },
            QStringLiteral("Ctrl+C"),
        }
        // Window menu
        // (come from TabWidget)
        // Help menu
        // (come from MainWindow)
    };

    if (ToggleCertificateEnabledCommand::isSupported()) {
        common_and_openpgp_action_data.push_back(action_data{
            "certificates_disable",
            i18nc("@action:inmenu", "Disable Certificate"),
            i18nc("@action:tooltip",
                  "Disabled certificates are not offered when selecting a certificate to sign with or to encrypt for.\nThey are still listed in the "
                  "certificate list."),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        });
    }

    static const action_data cms_create_csr_action_data = {
        "file_new_certificate_signing_request",
        i18n("New S/MIME Certification Request..."),
        i18n("Create a new S/MIME certificate signing request (CSR)"),
        "view-certificate-add",
        nullptr,
        nullptr,
        {},
    };

    static const std::vector<action_data> cms_action_data = {
        // Certificate menu
        {
            "certificates_trust_root",
            i18n("Trust Root Certificate"),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_distrust_root",
            i18n("Distrust Root Certificate"),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "certificates_dump_certificate",
            i18n("Technical Details"),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        // Tools menu
        {
            "tools_refresh_x509_certificates",
            i18n("Refresh S/MIME Certificates"),
            QString(),
            "view-refresh",
            nullptr,
            nullptr,
            QString(),
        },
        {
            "crl_clear_crl_cache",
            i18n("Clear CRL Cache"),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "crl_dump_crl_cache",
            i18n("Dump CRL Cache"),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
        {
            "crl_import_crl",
            i18n("Import CRL From File..."),
            QString(),
            nullptr,
            nullptr,
            nullptr,
            QString(),
        },
    };

    std::vector<action_data> action_data = common_and_openpgp_action_data;

    if (const Kleo::Settings settings{}; settings.cmsEnabled()) {
        if (settings.cmsCertificateCreationAllowed()) {
            action_data.push_back(cms_create_csr_action_data);
        }
        action_data.reserve(action_data.size() + cms_action_data.size());
        ranges::copy(cms_action_data, std::back_inserter(action_data));
    }

    make_actions_from_data(action_data, coll);

    if (QAction *action = coll->action(QStringLiteral("view_stop_operations"))) {
        connect(this, &KeyListController::commandsExecuting, action, &QAction::setEnabled);
    }

    // ### somehow make this better...
    registerActionForCommand<NewOpenPGPCertificateCommand>(coll->action(QStringLiteral("file_new_certificate")));
    registerActionForCommand<NewCertificateSigningRequestCommand>(coll->action(QStringLiteral("file_new_certificate_signing_request")));
    //---
    registerActionForCommand<LookupCertificatesCommand>(coll->action(QStringLiteral("file_lookup_certificates")));
    registerActionForCommand<ImportCertificateFromFileCommand>(coll->action(QStringLiteral("file_import_certificates")));
    //---
    registerActionForCommand<ExportCertificateCommand>(coll->action(QStringLiteral("file_export_certificates")));
    registerActionForCommand<ExportSecretKeyCommand>(coll->action(QStringLiteral("file_export_secret_keys")));
    registerActionForCommand<ExportPaperKeyCommand>(coll->action(QStringLiteral("file_export_paper_key")));
    registerActionForCommand<ExportOpenPGPCertsToServerCommand>(coll->action(QStringLiteral("file_export_certificates_to_server")));
#ifdef MAILAKONADI_ENABLED
    registerActionForCommand<ExportOpenPGPCertToProviderCommand>(coll->action(QStringLiteral("file_export_certificate_to_provider")));
#endif // MAILAKONADI_ENABLED
    registerActionForCommand<CertificateToCardCommand>(coll->action(QStringLiteral("certificate_to_card")));
    //---
    registerActionForCommand<DecryptVerifyFilesCommand>(coll->action(QStringLiteral("file_decrypt_verify_files")));
    registerActionForCommand<SignEncryptFilesCommand>(coll->action(QStringLiteral("file_sign_encrypt_files")));
    registerActionForCommand<SignEncryptFolderCommand>(coll->action(QStringLiteral("file_sign_encrypt_folder")));
    //---
    registerActionForCommand<ChecksumCreateFilesCommand>(coll->action(QStringLiteral("file_checksum_create_files")));
    registerActionForCommand<ChecksumVerifyFilesCommand>(coll->action(QStringLiteral("file_checksum_verify_files")));

    registerActionForCommand<ReloadKeysCommand>(coll->action(QStringLiteral("view_redisplay")));
    // coll->action( "view_stop_operations" ) <-- already dealt with in make_actions_from_data()
    registerActionForCommand<DetailsCommand>(coll->action(QStringLiteral("view_certificate_details")));

    registerActionForCommand<ChangeOwnerTrustCommand>(coll->action(QStringLiteral("certificates_change_owner_trust")));
    registerActionForCommand<TrustRootCommand>(coll->action(QStringLiteral("certificates_trust_root")));
    registerActionForCommand<DistrustRootCommand>(coll->action(QStringLiteral("certificates_distrust_root")));

    if (ToggleCertificateEnabledCommand::isSupported()) {
        registerActionForCommand<ToggleCertificateEnabledCommand>(coll->action(QStringLiteral("certificates_disable")));
    }

    //---
    registerActionForCommand<CertifyCertificateCommand>(coll->action(QStringLiteral("certificates_certify_certificate")));
    if (RevokeCertificationCommand::isSupported()) {
        registerActionForCommand<RevokeCertificationCommand>(coll->action(QStringLiteral("certificates_revoke_certification")));
    }
    //---
    registerActionForCommand<ChangeExpiryCommand>(coll->action(QStringLiteral("certificates_change_expiry")));
    registerActionForCommand<ChangePassphraseCommand>(coll->action(QStringLiteral("certificates_change_passphrase")));
    registerActionForCommand<AddUserIDCommand>(coll->action(QStringLiteral("certificates_add_userid")));
    registerActionForCommand<CreateGroupCommand>(coll->action(QStringLiteral("certificates_create_group")));
    //---
    registerActionForCommand<RevokeKeyCommand>(coll->action(QStringLiteral("certificates_revoke")));
    registerActionForCommand<DeleteCertificatesCommand>(coll->action(QStringLiteral("certificates_delete")));
    //---
    registerActionForCommand<RefreshCertificatesCommand>(coll->action(QStringLiteral("certificates_refresh")));
    //---
    registerActionForCommand<DumpCertificateCommand>(coll->action(QStringLiteral("certificates_dump_certificate")));

    registerActionForCommand<RefreshX509CertsCommand>(coll->action(QStringLiteral("tools_refresh_x509_certificates")));
    registerActionForCommand<RefreshOpenPGPCertsCommand>(coll->action(QStringLiteral("tools_refresh_openpgp_certificates")));
    //---
    registerActionForCommand<ImportCrlCommand>(coll->action(QStringLiteral("crl_import_crl")));
    //---
    registerActionForCommand<ClearCrlCacheCommand>(coll->action(QStringLiteral("crl_clear_crl_cache")));
    registerActionForCommand<DumpCrlCacheCommand>(coll->action(QStringLiteral("crl_dump_crl_cache")));

    enableDisableActions(nullptr);

    connect(KeyCache::instance().get(), &KeyCache::keysMayHaveChanged, this, [this, coll]() {
        d->updateActions(coll);
    });

    connect(this, &KeyListController::selectionChanged, this, [coll, this]() {
        d->updateActions(coll);
    });
}

void KeyListController::registerAction(QAction *action, Command::Restrictions restrictions, Command *(*create)(QAbstractItemView *, KeyListController *))
{
    if (!action) {
        return;
    }
    Q_ASSERT(!action->isCheckable()); // can be added later, for now, disallow

    const Private::action_item ai = {action, restrictions, create};
    connect(action, &QAction::triggered, this, [this, action]() {
        d->slotActionTriggered(action);
    });
    d->actions.push_back(ai);
}

void KeyListController::registerCommand(Command *cmd)
{
    if (!cmd || ranges::binary_search(d->commands, cmd)) {
        return;
    }
    d->addCommand(cmd);
    qCDebug(KLEOPATRA_LOG) << (void *)cmd;
    if (d->commands.size() == 1) {
        Q_EMIT commandsExecuting(true);
    }
}

bool KeyListController::hasRunningCommands() const
{
    return !d->commands.empty();
}

bool KeyListController::shutdownWarningRequired() const
{
    return ranges::any_of(d->commands, std::mem_fn(&Command::warnWhenRunningAtShutdown));
}

// slot
void KeyListController::cancelCommands()
{
    ranges::for_each(d->commands, std::mem_fn(&Command::cancel));
}

void KeyListController::Private::connectView(QAbstractItemView *view)
{
    connect(view, &QObject::destroyed, q, [this](QObject *obj) {
        slotDestroyed(obj);
    });
    connect(view, &QAbstractItemView::doubleClicked, q, [this](const QModelIndex &index) {
        slotDoubleClicked(index);
    });
    connect(view, &QAbstractItemView::activated, q, [this](const QModelIndex &index) {
        slotActivated(index);
    });
    connect(view->selectionModel(), &QItemSelectionModel::selectionChanged, q, [this](const QItemSelection &oldSel, const QItemSelection &newSel) {
        slotSelectionChanged(oldSel, newSel);
        Q_EMIT q->selectionChanged();
    });

    view->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(view, &QWidget::customContextMenuRequested, q, [this](const QPoint &pos) {
        slotContextMenu(pos);
    });
}

void KeyListController::Private::connectCommand(Command *cmd)
{
    if (!cmd) {
        return;
    }
    connect(cmd, &QObject::destroyed, q, [this](QObject *obj) {
        slotDestroyed(obj);
    });
    connect(cmd, &Command::finished, q, [this] {
        slotCommandFinished();
    });
    // connect( cmd, SIGNAL(canceled()), q, SLOT(slotCommandCanceled()) );
    connect(cmd, &Command::progress, q, &KeyListController::progress);
}

void KeyListController::Private::slotDoubleClicked(const QModelIndex &idx)
{
    QAbstractItemView *const view = qobject_cast<QAbstractItemView *>(q->sender());
    if (!view || !ranges::binary_search(views, view)) {
        return;
    }

    if (const auto *const keyListModel = dynamic_cast<KeyListModelInterface *>(view->model())) {
        DetailsCommand *const c = new DetailsCommand{keyListModel->key(idx)};
        c->setParentWidget(parentWidget ? parentWidget : view);
        c->start();
    }
}

void KeyListController::Private::slotActivated(const QModelIndex &idx)
{
    Q_UNUSED(idx)
    QAbstractItemView *const view = qobject_cast<QAbstractItemView *>(q->sender());
    if (!view || !ranges::binary_search(views, view)) {
        return;
    }
}

void KeyListController::Private::slotSelectionChanged(const QItemSelection &old, const QItemSelection &new_)
{
    Q_UNUSED(old)
    Q_UNUSED(new_)

    const QItemSelectionModel *const sm = qobject_cast<QItemSelectionModel *>(q->sender());
    if (!sm) {
        return;
    }
    q->enableDisableActions(sm);
}

void KeyListController::Private::slotContextMenu(const QPoint &p)
{
    QAbstractItemView *const view = qobject_cast<QAbstractItemView *>(q->sender());
    if (view && ranges::binary_search(views, view)) {
        Q_EMIT q->contextMenuRequested(view, view->viewport()->mapToGlobal(p));
    } else {
        qCDebug(KLEOPATRA_LOG) << "sender is not a QAbstractItemView*!";
    }
}

void KeyListController::Private::slotCommandFinished()
{
    Command *const cmd = qobject_cast<Command *>(q->sender());
    if (!cmd || !ranges::binary_search(commands, cmd)) {
        return;
    }
    qCDebug(KLEOPATRA_LOG) << (void *)cmd;
    if (commands.size() == 1) {
        Q_EMIT q->commandsExecuting(false);
    }
}

void KeyListController::enableDisableActions(const QItemSelectionModel *sm) const
{
    const Command::Restrictions restrictionsMask = d->calculateRestrictionsMask(sm);
    for (const Private::action_item &ai : std::as_const(d->actions))
        if (ai.action) {
            ai.action->setEnabled(ai.restrictions == (ai.restrictions & restrictionsMask));
        }
}

static bool all_secret_are_not_owner_trust_ultimate(const std::vector<Key> &keys)
{
    for (const Key &key : keys)
        if (key.hasSecret() && key.ownerTrust() == Key::Ultimate) {
            return false;
        }
    return true;
}

Command::Restrictions find_root_restrictions(const std::vector<Key> &keys)
{
    bool trusted = false, untrusted = false;
    for (const Key &key : keys)
        if (key.isRoot())
            if (key.userID(0).validity() == UserID::Ultimate) {
                trusted = true;
            } else {
                untrusted = true;
            }
        else {
            return Command::NoRestriction;
        }
    if (trusted)
        if (untrusted) {
            return Command::NoRestriction;
        } else {
            return Command::MustBeTrustedRoot;
        }
    else if (untrusted) {
        return Command::MustBeUntrustedRoot;
    } else {
        return Command::NoRestriction;
    }
}

static bool secretSubkeyDataAvailable(const Subkey &subkey)
{
    return subkey.isSecret() && !subkey.isCardKey();
}

Command::Restrictions KeyListController::Private::calculateRestrictionsMask(const QItemSelectionModel *sm)
{
    if (!sm) {
        return Command::NoRestriction;
    }

    const KeyListModelInterface *const m = dynamic_cast<const KeyListModelInterface *>(sm->model());
    if (!m) {
        return Command::NoRestriction;
    }

    const std::vector<Key> keys = m->keys(sm->selectedRows());
    if (keys.empty()) {
        return Command::NoRestriction;
    }

    Command::Restrictions result = Command::NeedSelection;

    if (keys.size() == 1) {
        result |= Command::OnlyOneKey;
    }

    // we need to check the primary subkey because Key::hasSecret() is also true if just the secret key stub of an offline key is available
    const auto primaryKeyCanBeUsedForSecretKeyOperations = [](const auto &k) {
        return k.subkey(0).isSecret();
    };
    if (ranges::all_of(keys, primaryKeyCanBeUsedForSecretKeyOperations)) {
        result |= Command::NeedSecretKey;
    }

    if (ranges::all_of(keys, [](const auto &k) {
            return ranges::any_of(k.subkeys(), &secretSubkeyDataAvailable);
        })) {
        result |= Command::NeedSecretSubkeyData;
    }
    if ((result & Command::NeedSecretSubkeyData) && ranges::all_of(keys, [](const auto &k) {
            return secretSubkeyDataAvailable(k.subkey(0));
        })) {
        result |= Command::NeedSecretPrimaryKeyData;
    }

    if (ranges::all_of(keys, [](const Key &key) {
            return key.protocol() == OpenPGP;
        })) {
        result |= Command::MustBeOpenPGP;
    } else if (ranges::all_of(keys, [](const Key &key) {
                   return key.protocol() == CMS;
               })) {
        result |= Command::MustBeCMS;
    }

    if (ranges::all_of(keys, [](const auto &key) {
            return !key.isBad();
        })) {
        result |= Command::MustBeValid;
    }

    if (all_secret_are_not_owner_trust_ultimate(keys)) {
        result |= Command::MayOnlyBeSecretKeyIfOwnerTrustIsNotYetUltimate;
    }

    result |= find_root_restrictions(keys);

    if (const ReaderStatus *rs = ReaderStatus::instance()) {
        if (!rs->firstCardWithNullPin().empty()) {
            result |= Command::AnyCardHasNullPin;
        }
    }

    {
        if (keys.size() > 0) {
            bool hasSignCertify = false;
            bool hasEncrypt = false;
            bool hasAuthenticate = false;
            bool invalid = false;
            for (const auto &subkey : keys[0].subkeys()) {
                if (subkey.isCardKey()) {
                    invalid = true;
                    break;
                }
                if (subkey.canCertify() && subkey.canSign()) {
                    if (hasSignCertify) {
                        invalid = true;
                        break;
                    } else {
                        hasSignCertify = true;
                    }
                } else if (subkey.canEncrypt()) {
                    if (hasEncrypt) {
                        invalid = true;
                        break;
                    } else {
                        hasEncrypt = true;
                    }
                } else if (subkey.canAuthenticate()) {
                    if (hasAuthenticate) {
                        invalid = true;
                        break;
                    } else {
                        hasAuthenticate = true;
                    }
                } else if (!subkey.canRenc()) { // we don't mind ADSKs
                    invalid = true;
                    break;
                }
            }
            if (hasSignCertify && hasEncrypt && !invalid) {
                result |= Command::SuitableForCard;
            }
        }
    }

    return result;
}

void KeyListController::Private::slotActionTriggered(QAction *sender)
{
    const auto it = ranges::find_if(actions, [sender](const action_item &item) {
        return item.action == sender;
    });
    if (it != actions.end())
        if (Command *const c = it->createCommand(this->currentView, q)) {
            if (parentWidget) {
                c->setParentWidget(parentWidget);
            }
            c->start();
        } else
            qCDebug(KLEOPATRA_LOG) << "createCommand() == NULL for action(?) \"" << qPrintable(sender->objectName()) << "\"";
    else {
        qCDebug(KLEOPATRA_LOG) << "I don't know anything about action(?) \"%s\"", qPrintable(sender->objectName());
    }
}

int KeyListController::Private::toolTipOptions() const
{
    using namespace Kleo::Formatting;
    static const int validityFlags = Validity | Issuer | ExpiryDates | CertificateUsage;
    static const int ownerFlags = Subject | UserIDs | OwnerTrust;
    static const int detailsFlags = StorageLocation | CertificateType | SerialNumber | Fingerprint;

    const TooltipPreferences prefs;

    int flags = KeyID;
    flags |= prefs.showValidity() ? validityFlags : 0;
    flags |= prefs.showOwnerInformation() ? ownerFlags : 0;
    flags |= prefs.showCertificateDetails() ? detailsFlags : 0;
    return flags;
}

void KeyListController::updateConfig()
{
    const int opts = d->toolTipOptions();
    if (d->flatModel) {
        d->flatModel->setToolTipOptions(opts);
    }
    if (d->hierarchicalModel) {
        d->hierarchicalModel->setToolTipOptions(opts);
    }
}

void KeyListController::Private::updateActions(KActionCollection *collection)
{
    if (ToggleCertificateEnabledCommand::isSupported() && q->currentView()) {
        auto key = q->currentView()->selectionModel()->currentIndex().data(KeyList::KeyRole).value<GpgME::Key>();
        if (key.isNull() || !key.primaryFingerprint()) {
            return;
        }
        // Get the key from the cache, as the existing one isn't correctly updated yet
        key = KeyCache::instance()->findByKeyIDOrFingerprint(key.primaryFingerprint());
        auto action = collection->action(QStringLiteral("certificates_disable"));
        action->setText(key.isDisabled() ? i18nc("@action:inmenu", "Enable Certificate") : i18nc("@action:inmenu", "Disable Certificate"));
    }
}

#include "moc_keylistcontroller.cpp"
