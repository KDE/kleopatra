/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "mainwindow.h"
#include "kleopatraapplication.h"
#include "settings.h"
#include <config-kleopatra.h>

#include <interfaces/focusfirstchild.h>

#include "view/keycacheoverlay.h"
#include "view/keylistcontroller.h"
#include "view/searchbar.h"
#include "view/tabwidget.h"
#include "view/welcomewidget.h"

#include "commands/decryptverifyfilescommand.h"
#include "commands/importcertificatefromfilecommand.h"
#include "commands/importcrlcommand.h"
#include "commands/selftestcommand.h"
#include "commands/signencryptfilescommand.h"

#include "utils/action_data.h"
#include "utils/clipboardmenu.h"
#include "utils/detail_p.h"
#include "utils/filedialog.h"
#include "utils/gui-helper.h"
#include "utils/keyexportdraghandler.h"
#include "utils/userinfo.h"

#include <Libkleo/ApplicationPaletteWatcher>
#include <Libkleo/GnuPG>

#include "dialogs/debugdialog.h"
#include "dialogs/padwindow.h"
#include "dialogs/updatenotification.h"

// needed for GPGME_VERSION_NUMBER
#include <gpgme.h>

#include "kleopatra_debug.h"
#include <KAboutData>
#include <KActionCollection>
#include <KActionMenu>
#include <KColorScheme>
#include <KColorSchemeManager>
#include <KColorSchemeMenu>
#include <KConfigDialog>
#include <KConfigGroup>
#include <KEditToolBar>
#include <KHelpMenu>
#include <KLocalizedString>
#include <KMessageBox>
#include <KShortcutsDialog>
#include <KStandardAction>
#include <KStandardGuiItem>
#include <KToolBar>
#include <KXMLGUIFactory>
#include <QAction>
#include <QApplication>
#include <QLineEdit>
#include <QSize>

#include <QAbstractItemView>
#include <QCloseEvent>
#include <QDesktopServices>
#include <QDir>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QMimeData>
#include <QPixmap>
#include <QProcess>
#include <QSettings>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTimer>
#include <QVBoxLayout>

#include <Libkleo/Classify>
#include <Libkleo/Compliance>
#include <Libkleo/DocAction>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyListModel>
#include <Libkleo/KeyListSortFilterProxyModel>
#include <Libkleo/Stl_Util>
#include <Libkleo/SystemInfo>

#include <KSharedConfig>

#include <chrono>
#include <vector>
using namespace std::chrono_literals;

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

using namespace Qt::Literals::StringLiterals;

static KGuiItem KStandardGuiItem_quit()
{
    static const QString app = KAboutData::applicationData().displayName();
    KGuiItem item = KStandardGuiItem::quit();
    item.setText(xi18nc("@action:button", "&Quit <application>%1</application>", app));
    return item;
}

static KGuiItem KStandardGuiItem_close()
{
    KGuiItem item = KStandardGuiItem::close();
    item.setText(i18nc("@action:button", "Only &Close Window"));
    return item;
}

static bool isQuitting = false;

namespace
{

class CertificateView : public QWidget, public FocusFirstChild
{
    Q_OBJECT
public:
    explicit CertificateView(QWidget *parent = nullptr)
        : QWidget{parent}
        , ui{this}
    {
    }

    SearchBar *searchBar() const
    {
        return ui.searchBar;
    }

    TabWidget *tabWidget() const
    {
        return ui.tabWidget;
    }

    void focusFirstChild(Qt::FocusReason reason) override
    {
        ui.searchBar->lineEdit()->setFocus(reason);
    }

private:
    struct UI {
        TabWidget *tabWidget = nullptr;
        SearchBar *searchBar = nullptr;
        explicit UI(CertificateView *q)
        {
            auto vbox = new QVBoxLayout{q};
            vbox->setSpacing(0);

            searchBar = new SearchBar{q};
            vbox->addWidget(searchBar);
            tabWidget = new TabWidget{KeyTreeView::Option::NoDefaultContextMenu, q};
            vbox->addWidget(tabWidget);

            tabWidget->connectSearchBar(searchBar);
        }
    } ui;
};

}

class MainWindow::Private
{
    friend class ::MainWindow;
    MainWindow *const q;

public:
    explicit Private(MainWindow *qq);
    ~Private();

    template<typename T>
    void createAndStart()
    {
        (new T(this->currentView(), &this->controller))->start();
    }
    template<typename T>
    void createAndStart(QAbstractItemView *view)
    {
        (new T(view, &this->controller))->start();
    }
    template<typename T>
    void createAndStart(const QStringList &a)
    {
        (new T(a, this->currentView(), &this->controller))->start();
    }
    template<typename T>
    void createAndStart(const QStringList &a, QAbstractItemView *view)
    {
        (new T(a, view, &this->controller))->start();
    }

    void closeAndQuit()
    {
        if (qApp->quitOnLastWindowClosed()) {
            qApp->quit();
        }

        const QString app = KAboutData::applicationData().displayName();
        const int rc = KMessageBox::questionTwoActionsCancel(q,
                                                             xi18nc("@info",
                                                                    "<application>%1</application> may be used by other applications as a service.<nl/>"
                                                                    "You may instead want to close this window without exiting <application>%1</application>.",
                                                                    app),
                                                             i18nc("@title:window", "Really Quit?"),
                                                             KStandardGuiItem_close(),
                                                             KStandardGuiItem_quit(),
                                                             KStandardGuiItem::cancel(),
                                                             QLatin1StringView("really-quit-") + app.toLower());
        if (rc == KMessageBox::Cancel) {
            return;
        }
        isQuitting = rc == KMessageBox::ButtonCode::SecondaryAction;
        if (!q->close()) {
            return;
        }
        // WARNING: 'this' might be deleted at this point!
        if (rc == KMessageBox::ButtonCode::SecondaryAction) {
            qApp->quit();
        }
    }
    void configureToolbars()
    {
        KEditToolBar dlg(q->factory());
        dlg.exec();
    }
    void editKeybindings()
    {
        KShortcutsDialog::showDialog(q->actionCollection(), KShortcutsEditor::LetterShortcutsAllowed, q);
        updateSearchBarClickMessage();
    }

    void updateSearchBarClickMessage()
    {
        const QString shortcutStr = focusToClickSearchAction->shortcut().toString(QKeySequence::NativeText);
        ui.searchTab->searchBar()->updateClickMessage(shortcutStr);
    }

    void updateStatusBar()
    {
        auto statusBar = std::make_unique<QStatusBar>();
        auto settings = KleopatraApplication::instance()->distributionSettings();
        bool showStatusbar = false;
        if (settings) {
            const QString statusline = settings->value(QStringLiteral("statusline"), {}).toString();
            if (!statusline.isEmpty()) {
                auto customStatusLbl = new QLabel(statusline);
                statusBar->insertWidget(0, customStatusLbl);
                showStatusbar = true;
            }
        }
        if (DeVSCompliance::isActive()) {
            auto statusLbl = std::make_unique<QLabel>(DeVSCompliance::name());
            {
                auto statusPalette = qApp->palette();
                KColorScheme::adjustForeground(statusPalette,
                                               DeVSCompliance::isCompliant() ? KColorScheme::NormalText : KColorScheme::NegativeText,
                                               statusLbl->foregroundRole(),
                                               KColorScheme::View);
                statusLbl->setAutoFillBackground(true);
                KColorScheme::adjustBackground(statusPalette,
                                               DeVSCompliance::isCompliant() ? KColorScheme::PositiveBackground : KColorScheme::NegativeBackground,
                                               QPalette::Window,
                                               KColorScheme::View);
                statusLbl->setPalette(statusPalette);
            }
            statusBar->insertPermanentWidget(0, statusLbl.release());
            showStatusbar = true;
        }

        if (showStatusbar) {
            q->setStatusBar(statusBar.release()); // QMainWindow takes ownership
        } else {
            q->setStatusBar(nullptr);
        }
    }

    void selfTest()
    {
        createAndStart<SelfTestCommand>();
    }

    void configureGroups()
    {
        // open groups config dialog as independent top-level window
        KleopatraApplication::instance()->openOrRaiseGroupsConfigDialog(nullptr);
    }

    void showHandbook();

    void gnupgLogViewer()
    {
        // Warning: Don't assume that the program needs to be in PATH. On Windows, it will also be found next to the calling process.
        if (!QProcess::startDetached(QStringLiteral("kwatchgnupg"), QStringList()))
            KMessageBox::error(q,
                               i18n("Could not start the GnuPG Log Viewer (kwatchgnupg). "
                                    "Please check your installation."),
                               i18n("Error Starting KWatchGnuPG"));
    }

    void forceUpdateCheck()
    {
        UpdateNotification::forceUpdateCheck(q);
    }

    void slotConfigCommitted();
    void slotContextMenuRequested(QAbstractItemView *, const QPoint &p)
    {
        if (auto const menu = qobject_cast<QMenu *>(q->factory()->container(QStringLiteral("listview_popup"), q))) {
            menu->exec(p);
        } else {
            qCDebug(KLEOPATRA_LOG) << "no \"listview_popup\" <Menu> in kleopatra's ui.rc file";
        }
    }

    void slotFocusQuickSearch()
    {
        ui.searchTab->searchBar()->lineEdit()->setFocus();
    }

    void showView(QWidget *widget)
    {
        ui.stackWidget->setCurrentWidget(widget);
        if (auto ffci = dynamic_cast<Kleo::FocusFirstChild *>(widget)) {
            ffci->focusFirstChild(Qt::TabFocusReason);
        }
    }

    void showPadView()
    {
        auto padWindow = new PadWindow();
        padWindow->setAttribute(Qt::WA_DeleteOnClose);
        padWindow->show();
    }

    void restartDaemons()
    {
        Kleo::restartGpgAgent();
    }

private:
    void setupActions();

    QAbstractItemView *currentView() const
    {
        return ui.searchTab->tabWidget()->currentView();
    }

    void keyListingDone()
    {
        if (KeyCache::instance()->keys().empty()) {
            showView(ui.welcomeWidget);
        } else {
            showView(ui.searchTab);
        }
    }

private:
    ApplicationPaletteWatcher appPaletteWatcher;
    Kleo::KeyListController controller;
    bool firstShow : 1;
    struct UI {
        CertificateView *searchTab = nullptr;
        WelcomeWidget *welcomeWidget = nullptr;
        QStackedWidget *stackWidget = nullptr;
        explicit UI(MainWindow *q);
    } ui;
    QAction *focusToClickSearchAction = nullptr;
    ClipboardMenu *clipboadMenu = nullptr;
};

MainWindow::Private::UI::UI(MainWindow *q)
{
    auto mainWidget = new QWidget{q};
    auto mainLayout = new QVBoxLayout(mainWidget);
    mainLayout->setContentsMargins({});
    stackWidget = new QStackedWidget{q};

    searchTab = new CertificateView{q};
    stackWidget->addWidget(searchTab);

    new KeyCacheOverlay(mainWidget, q);

    welcomeWidget = new WelcomeWidget{q};
    stackWidget->addWidget(welcomeWidget);

    mainLayout->addWidget(stackWidget);

    q->setCentralWidget(mainWidget);
}

MainWindow::Private::Private(MainWindow *qq)
    : q(qq)
    , controller(q)
    , firstShow(true)
    , ui(q)
{
    Q_SET_OBJECT_NAME(controller);

    AbstractKeyListModel *flatModel = AbstractKeyListModel::createFlatKeyListModel(q);
    AbstractKeyListModel *hierarchicalModel = AbstractKeyListModel::createHierarchicalKeyListModel(q);

    Q_SET_OBJECT_NAME(flatModel);
    Q_SET_OBJECT_NAME(hierarchicalModel);

// check for GpgME >= 1.24.0
#if GPGME_VERSION_NUMBER >= 0x011800 && !defined(Q_OS_WIN)
    auto keyExportDragHandler = std::make_shared<KeyExportDragHandler>();
    flatModel->setDragHandler(keyExportDragHandler);
    hierarchicalModel->setDragHandler(keyExportDragHandler);
#endif

    controller.setFlatModel(flatModel);
    controller.setHierarchicalModel(hierarchicalModel);
    controller.setTabWidget(ui.searchTab->tabWidget());

    ui.searchTab->tabWidget()->setFlatModel(flatModel);
    ui.searchTab->tabWidget()->setHierarchicalModel(hierarchicalModel);

    setupActions();

    ui.stackWidget->setCurrentWidget(ui.searchTab);

    connect(&controller, SIGNAL(contextMenuRequested(QAbstractItemView *, QPoint)), q, SLOT(slotContextMenuRequested(QAbstractItemView *, QPoint)));
    connect(KeyCache::instance().get(), &KeyCache::keyListingDone, q, [this]() {
        keyListingDone();
    });

    q->createGUI(QStringLiteral("kleopatra.rc"));

    if (auto helpMenu = q->findChild<KHelpMenu *>()) {
        qCDebug(KLEOPATRA_LOG) << "Hook into the help menu to show the About dialog ourselves";
        connect(helpMenu, &KHelpMenu::showAboutApplication, KleopatraApplication::instance(), &KleopatraApplication::showAboutDialog);
    }

    // make toolbar buttons accessible by keyboard
    auto toolbar = q->findChild<KToolBar *>();
    if (toolbar) {
        const auto toolbarButtons = toolbar->findChildren<QToolButton *>();
        for (auto b : toolbarButtons) {
            b->setFocusPolicy(Qt::TabFocus);
        }
        // move toolbar and its child widgets before the central widget in the tab order;
        // this is necessary to make Shift+Tab work as expected
        forceSetTabOrder(q, toolbar);
        auto toolbarChildren = toolbar->findChildren<QWidget *>();
        std::for_each(std::rbegin(toolbarChildren), std::rend(toolbarChildren), [toolbar](auto w) {
            forceSetTabOrder(toolbar, w);
        });
    }

    if (auto action = q->actionCollection()->action(QStringLiteral("help_whats_this"))) {
        delete action;
    }

    q->setAcceptDrops(true);

    // set default window size
    q->resize(QSize(1024, 500));
    q->setAutoSaveSettings();

    updateSearchBarClickMessage();
    connect(&appPaletteWatcher, &ApplicationPaletteWatcher::paletteChanged, q, [this]() {
        updateStatusBar();
    });
    connect(KleopatraApplication::instance(), &KleopatraApplication::distributionSettingsChanged, q, [this]() {
        updateStatusBar();
    });
    updateStatusBar();

    if (KeyCache::instance()->initialized()) {
        keyListingDone();
    }

    // delay setting the models to use the key cache so that the UI (including
    // the "Loading certificate cache..." overlay) is shown before the
    // blocking key cache initialization happens
    QMetaObject::invokeMethod(
        q,
        [flatModel, hierarchicalModel]() {
            flatModel->useKeyCache(true, KeyList::AllKeys);
            hierarchicalModel->useKeyCache(true, KeyList::AllKeys);
        },
        Qt::QueuedConnection);
}

MainWindow::Private::~Private()
{
}

MainWindow::MainWindow(QWidget *parent, Qt::WindowFlags flags)
    : KXmlGuiWindow(parent, flags)
    , d(new Private(this))
{
}

MainWindow::~MainWindow()
{
}

void MainWindow::Private::setupActions()
{
    KActionCollection *const coll = q->actionCollection();

    const std::vector<action_data> action_data = {
    // see keylistcontroller.cpp for more actions
    // Tools menu
#ifndef Q_OS_WIN
        {
            "tools_start_kwatchgnupg",
            i18n("GnuPG Log Viewer"),
            QString(),
            "org.kde.kwatchgnupg",
            q,
            [this](bool) {
                gnupgLogViewer();
            },
            QString(),
        },
#endif
        {
            "tools_debug_view",
            i18n("GnuPG Command Line"),
            QString(),
            "",
            q,
            [this](bool) {
                auto dialog = new DebugDialog(q);
                dialog->setAttribute(Qt::WA_DeleteOnClose);
                dialog->open();
            },
            QString(),
        },
        {
            "tools_restart_backend",
            i18nc("@action:inmenu", "Restart Background Processes"),
            i18nc("@info:tooltip", "Restart the background processes, e.g. after making changes to the configuration."),
            "view-refresh",
            q,
            [this](bool) {
                restartDaemons();
            },
            {},
        },
    // Help menu
#ifdef Q_OS_WIN
        {
            "help_check_updates",
            i18n("Check for updates"),
            QString(),
            "gpg4win-compact",
            q,
            [this](bool) {
                forceUpdateCheck();
            },
            QString(),
        },
#endif
        // View menu
        {
            "pad_view",
            i18nc("@action show input / output area for encrypting/signing resp. decrypting/verifying text", "Notepad"),
            i18n("Show pad for encrypting/decrypting and signing/verifying text"),
            "note",
            q,
            [this](bool) {
                showPadView();
            },
            QString(),
        },
        {
            "manage_smartcard",
            i18nc("@action show smartcard management view", "Smartcards"),
            i18n("Show smartcard management"),
            "auth-sim-locked",
            q,
            [](bool) {
                KleopatraApplication::instance()->openOrRaiseSmartCardWindow();
            },
            QString(),
        },
        {
            "move_column_front",
            i18nc("@action:inmenu", "Move column to front"),
            i18nc("@info", "Move the current column to the beginning of the table"),
            "arrow-left-double",
            q,
            [this](bool) {
                auto treeView = dynamic_cast<TreeView *>(ui.searchTab->tabWidget()->currentView());
                auto logicalIndex = treeView->currentIndex().column();
                auto visualIndex = treeView->header()->visualIndex(logicalIndex);
                treeView->header()->moveSection(visualIndex, 0);
            },
            QString(),
        },
        {
            "move_column_left",
            i18nc("@action:inmenu", "Move column left"),
            i18nc("@info", "Move the current column to the left"),
            "arrow-left",
            q,
            [this](bool) {
                auto treeView = dynamic_cast<TreeView *>(ui.searchTab->tabWidget()->currentView());
                auto logicalIndex = treeView->currentIndex().column();
                auto visualIndex = treeView->header()->visualIndex(logicalIndex);
                treeView->header()->moveSection(visualIndex, visualIndex - 1);
            },
            QString(),
        },
        {
            "move_column_right",
            i18nc("@action:inmenu", "Move column right"),
            i18nc("@info", "Move the current column to the right"),
            "arrow-right",
            q,
            [this](bool) {
                auto treeView = dynamic_cast<TreeView *>(ui.searchTab->tabWidget()->currentView());
                auto logicalIndex = treeView->currentIndex().column();
                auto visualIndex = treeView->header()->visualIndex(logicalIndex);
                treeView->header()->moveSection(visualIndex, visualIndex + 1);
            },
            QString(),
        },
        {
            "move_column_back",
            i18nc("@action:inmenu", "Move column to the back"),
            i18nc("@info", "Move the current column to the end of the table"),
            "arrow-right-double",
            q,
            [this](bool) {
                auto treeView = dynamic_cast<TreeView *>(ui.searchTab->tabWidget()->currentView());
                auto logicalIndex = treeView->currentIndex().column();
                auto visualIndex = treeView->header()->visualIndex(logicalIndex);
                treeView->header()->moveSection(visualIndex, treeView->model()->columnCount({}) - 1);
            },
            QString(),
        },
        // Settings menu
        {
            "settings_self_test",
            i18n("Perform Self-Test"),
            QString(),
            nullptr,
            q,
            [this](bool) {
                selfTest();
            },
            QString(),
        },
        {
            "configure_groups",
            i18n("Manage Groups..."),
            QString(),
            "group",
            q,
            [this](bool) {
                configureGroups();
            },
            QString(),
        },
        // Toolbar
        {
            "configure_groups_toolbar",
            i18nc("@action:intoolbar", "Groups"),
            QString(),
            "group",
            q,
            [this](bool) {
                configureGroups();
            },
            QString(),
        }};

    make_actions_from_data(action_data, coll);

    if (!Settings().groupsEnabled()) {
        if (auto action = coll->action(QStringLiteral("configure_groups"))) {
            delete action;
        }
        if (auto action = coll->action(QStringLiteral("configure_groups_toolbar"))) {
            delete action;
        }
    }

    KStandardAction::close(q, SLOT(close()), coll);
    KStandardAction::quit(q, SLOT(closeAndQuit()), coll);
    KStandardAction::configureToolbars(q, SLOT(configureToolbars()), coll);
    KStandardAction::keyBindings(q, SLOT(editKeybindings()), coll);
    KStandardAction::preferences(qApp, SLOT(openOrRaiseConfigDialog()), coll);

    auto manager = KColorSchemeManager::instance();
    KActionMenu *schemeMenu = KColorSchemeMenu::createMenu(manager, q);
    coll->addAction(QStringLiteral("colorscheme_menu"), schemeMenu->menu()->menuAction());

    focusToClickSearchAction = new QAction(i18nc("@action", "Set Focus to Quick Search"), q);
    coll->addAction(QStringLiteral("focus_to_quickseach"), focusToClickSearchAction);
    coll->setDefaultShortcut(focusToClickSearchAction, QKeySequence(Qt::ALT | Qt::Key_Q));
    connect(focusToClickSearchAction, SIGNAL(triggered(bool)), q, SLOT(slotFocusQuickSearch()));
    clipboadMenu = new ClipboardMenu(q);
    clipboadMenu->setMainWindow(q);
    clipboadMenu->clipboardMenu()->setIcon(QIcon::fromTheme(QStringLiteral("edit-paste")));
    clipboadMenu->clipboardMenu()->setPopupMode(QToolButton::InstantPopup);
    coll->addAction(QStringLiteral("clipboard_menu"), clipboadMenu->clipboardMenu());

    /* Add additional help actions for documentation */
    const auto compendium = new DocAction(QIcon{u":/gpg4win/gpg4win-compact"_s},
                                          i18n("Gpg4win Compendium"),
                                          i18nc("The Gpg4win compendium is only available"
                                                "at this point (24.7.2017) in german and english."
                                                "Please check with Gpg4win before translating this filename.",
                                                "gpg4win-compendium-en.pdf"),
                                          QStringLiteral("../share/gpg4win"),
                                          QUrl(),
                                          coll);
    coll->addAction(QStringLiteral("help_doc_compendium"), compendium);

    /* Documentation centered around the german approved VS-NfD mode for official
     * RESTRICTED communication. This is only available in some distributions with
     * the focus on official communications. */
    const auto quickguide =
        new DocAction(QIcon::fromTheme(QStringLiteral("help-contextual")),
                      i18n("&Quick Guide Encrypt and Sign"),
                      i18nc("Only available in German and English. Leave to English for other languages.", "encrypt_and_sign_gnupgvsd_en.pdf"),
                      QStringLiteral("../share/doc/gnupg-vsd"),
                      QUrl(),
                      coll);
    coll->addAction(QStringLiteral("help_doc_quickguide"), quickguide);

    coll->addAction(QStringLiteral("help_doc_symenc"), createSymmetricGuideAction(coll).release());

    const auto groups = new DocAction(QIcon::fromTheme(QStringLiteral("help-contextual")),
                                      i18n("Certificate &Groups"),
                                      i18nc("Only available in German and English. Leave to English for other languages.", "groupfeature_gnupgvsd_en.pdf"),
                                      QStringLiteral("../share/doc/gnupg-vsd"),
                                      QUrl(),
                                      coll);
    coll->addAction(QStringLiteral("help_doc_groups"), groups);

#ifdef Q_OS_WIN
    const auto gpgol =
        new DocAction(QIcon::fromTheme(QStringLiteral("help-contextual")),
                      i18n("&Mail Encryption in Outlook"),
                      i18nc("Only available in German and English. Leave to English for other languages. Only shown on Windows.", "gpgol_outlook_addin_en.pdf"),
                      QStringLiteral("../share/doc/gnupg-vsd"),
                      QUrl(),
                      coll);
    coll->addAction(QStringLiteral("help_doc_gpgol"), gpgol);
#endif

    /* The submenu with advanced topics */
    const auto certmngmnt =
        new DocAction(QIcon::fromTheme(QStringLiteral("help-contextual")),
                      i18n("&Certification Management"),
                      i18nc("Only available in German and English. Leave to English for other languages.", "certification_management_gnupgvsd_en.pdf"),
                      QStringLiteral("../share/doc/gnupg-vsd"),
                      QUrl(),
                      coll);
    coll->addAction(QStringLiteral("help_doc_cert_management"), certmngmnt);

    const auto smartcard =
        new DocAction(QIcon::fromTheme(QStringLiteral("help-contextual")),
                      i18n("&Smartcard Setup"),
                      i18nc("Only available in German and English. Leave to English for other languages.", "smartcard_setup_gnupgvsd_en.pdf"),
                      QStringLiteral("../share/doc/gnupg-vsd"),
                      QUrl(),
                      coll);
    coll->addAction(QStringLiteral("help_doc_smartcard"), smartcard);

    const auto man_gnupg = new DocAction(QIcon::fromTheme(QStringLiteral("help-contextual")),
                                         i18n("GnuPG Command&line"),
                                         QStringLiteral("gnupg_manual_en.pdf"),
                                         QStringLiteral("../share/doc/gnupg-vsd"),
                                         QUrl(QStringLiteral("https://gnupg.org/documentation/manuals/gnupg/")),
                                         coll);
    coll->addAction(QStringLiteral("help_doc_gnupg"), man_gnupg);

    /* The secops */
    const auto approvalmanual =
        new DocAction(QIcon::fromTheme(QStringLiteral("dvipdf")),
                      i18n("Manual for VS-NfD Approval"),
                      i18nc("Only available in German and English. Keep the English file name for other languages.", "handbuch_zulassung_gnupgvsd_en.pdf"),
                      QStringLiteral("../share/doc/gnupg-vsd"),
                      QUrl(),
                      coll);
    coll->addAction(QStringLiteral("help_doc_approval_manual"), approvalmanual);

    const auto vsa =
        new DocAction(QIcon::fromTheme(QStringLiteral("dvipdf")),
                      i18n("SecOps for VS-NfD Approval"),
                      i18nc("Only available in German and English. Keep the English file name for other languages.", "BSI-VSA-10867_ENG_secops.pdf"),
                      QStringLiteral("../share/doc/gnupg-vsd"),
                      QUrl(),
                      coll);
    coll->addAction(QStringLiteral("help_doc_vsa"), vsa);

    q->setStandardToolBarMenuEnabled(true);

    controller.createActions(coll);

    ui.searchTab->tabWidget()->createActions(coll);
}

void MainWindow::Private::slotConfigCommitted()
{
    controller.updateConfig();
    updateStatusBar();
}

bool MainWindow::queryClose()
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    if (d->controller.hasRunningCommands()) {
        if (d->controller.shutdownWarningRequired()) {
            const int ret = KMessageBox::warningContinueCancel(this,
                                                               i18n("There are still some background operations ongoing. "
                                                                    "These will be terminated when closing the window. "
                                                                    "Proceed?"),
                                                               i18n("Ongoing Background Tasks"));
            if (ret != KMessageBox::Continue) {
                return false;
            }
        }
        d->controller.cancelCommands();
        if (d->controller.hasRunningCommands()) {
            // wait for them to be finished:
            setEnabled(false);
            QEventLoop ev;
            QTimer::singleShot(100ms, &ev, &QEventLoop::quit);
            connect(&d->controller, &KeyListController::commandsExecuting, &ev, &QEventLoop::quit);
            ev.exec();
            if (d->controller.hasRunningCommands()) {
                qCWarning(KLEOPATRA_LOG) << "controller still has commands running, this may crash now...";
            }
            setEnabled(true);
        }
    }
    if (isQuitting || qApp->isSavingSession() || qApp->quitOnLastWindowClosed()) {
        d->ui.searchTab->tabWidget()->saveViews();
        return true;
    } else {
        hide();
        return false;
    }
}

void MainWindow::showEvent(QShowEvent *e)
{
    KXmlGuiWindow::showEvent(e);
    if (d->firstShow) {
        d->ui.searchTab->tabWidget()->loadViews(KSharedConfig::openStateConfig(), QStringLiteral("KeyList"));
        d->firstShow = false;
    }

    if (!savedGeometry.isEmpty()) {
        restoreGeometry(savedGeometry);
    }
}

void MainWindow::hideEvent(QHideEvent *e)
{
    savedGeometry = saveGeometry();
    KXmlGuiWindow::hideEvent(e);
}

void MainWindow::importCertificatesFromFile(const QStringList &files)
{
    if (!files.empty()) {
        d->createAndStart<ImportCertificateFromFileCommand>(files);
    }
}

static QStringList extract_local_files(const QMimeData *data)
{
    const QList<QUrl> urls = data->urls();
    // begin workaround KDE/Qt misinterpretation of text/uri-list
    QList<QUrl>::const_iterator end = urls.end();
    if (urls.size() > 1 && !urls.back().isValid()) {
        --end;
    }
    // end workaround
    QStringList result;
    std::transform(urls.begin(), end, std::back_inserter(result), std::mem_fn(&QUrl::toLocalFile));
    result.erase(std::remove_if(result.begin(), result.end(), std::mem_fn(&QString::isEmpty)), result.end());
    return result;
}

static bool can_decode_local_files(const QMimeData *data)
{
    if (!data) {
        return false;
    }
    return !extract_local_files(data).empty();
}

void MainWindow::dragEnterEvent(QDragEnterEvent *e)
{
    qCDebug(KLEOPATRA_LOG);

    if (can_decode_local_files(e->mimeData())) {
        e->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *e)
{
    qCDebug(KLEOPATRA_LOG);

    if (e->source()) {
        // The event comes from kleopatra itself; we don't want to import in this case.
        return;
    }

    if (!can_decode_local_files(e->mimeData())) {
        return;
    }

    e->setDropAction(Qt::CopyAction);

    const QStringList files = extract_local_files(e->mimeData());

    KleopatraApplication::instance()->handleFiles(files);

    e->accept();
}

void MainWindow::readProperties(const KConfigGroup &cg)
{
    qCDebug(KLEOPATRA_LOG);
    KXmlGuiWindow::readProperties(cg);
    setHidden(cg.readEntry("hidden", false));
}

void MainWindow::saveProperties(KConfigGroup &cg)
{
    qCDebug(KLEOPATRA_LOG);
    KXmlGuiWindow::saveProperties(cg);
    cg.writeEntry("hidden", isHidden());
}

KeyListController *MainWindow::keyListController()
{
    return &d->controller;
}

std::unique_ptr<DocAction> MainWindow::createSymmetricGuideAction(QObject *parent)
{
    return std::make_unique<DocAction>(
        QIcon::fromTheme(QStringLiteral("help-contextual")),
        i18n("&Password-based Encryption"),
        i18nc("Only available in German and English. Leave to English for other languages.", "symmetric_encryption_gnupgvsd_en.pdf"),
        QStringLiteral("../share/doc/gnupg-vsd"),
        QUrl(),
        parent);
}

#include "mainwindow.moc"
#include "moc_mainwindow.cpp"
