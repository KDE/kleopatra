/*
    kleopatraapplication.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "kleopatraapplication.h"

#include "kleopatra_options.h"
#include "mainwindow.h"
#include "settings.h"
#include "smimevalidationpreferences.h"
#include "systrayicon.h"

#include <conf/configuredialog.h>
#include <conf/groupsconfigdialog.h>
#include <smartcard/readerstatus.h>

#include <Libkleo/GnuPG>
#include <utils/kdpipeiodevice.h>
#include <utils/log.h>
#include <utils/userinfo.h>

#include <gpgme++/key.h>

#include <Libkleo/Classify>
#include <Libkleo/Dn>
#include <Libkleo/FileSystemWatcher>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyFilterManager>
#include <Libkleo/KeyGroupConfig>
#include <Libkleo/SystemInfo>

#include <uiserver/uiserver.h>

#include "commands/checksumcreatefilescommand.h"
#include "commands/checksumverifyfilescommand.h"
#include "commands/decryptverifyfilescommand.h"
#include "commands/detailscommand.h"
#include "commands/importcertificatefromfilecommand.h"
#include "commands/lookupcertificatescommand.h"
#include "commands/newcertificatesigningrequestcommand.h"
#include "commands/newopenpgpcertificatecommand.h"
#include "commands/signencryptfilescommand.h"

#include "dialogs/updatenotification.h"

#ifdef Q_OS_WIN
#include <utils/winapi-helpers.h>
#endif

#include "kleopatra_debug.h"
#include <KColorSchemeManager>
#include <KIconLoader>
#include <KLocalizedString>
#include <KMessageBox>
#include <KWindowSystem>

#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFocusFrame>
#if QT_CONFIG(graphicseffect)
#include <QGraphicsEffect>
#endif
#include <QPointer>
#include <QSettings>
#include <QStyleOption>
#include <QStylePainter>

#include <KSharedConfig>
#include <memory>

#ifdef Q_OS_WIN
#include <QtPlatformHeaders/QWindowsWindowFunctions>

#include <windows.h>
#endif

using namespace Kleo;
using namespace Kleo::Commands;

static void add_resources()
{
    KIconLoader::global()->addAppDir(QStringLiteral("libkleopatra"));
    KIconLoader::global()->addAppDir(QStringLiteral("kwatchgnupg"));
}

static QList<QByteArray> default_logging_options()
{
    QList<QByteArray> result;
    result.push_back("io");
    return result;
}

namespace
{
class FocusFrame : public QFocusFrame
{
    Q_OBJECT
public:
    using QFocusFrame::QFocusFrame;

protected:
    void paintEvent(QPaintEvent *event) override;
};

static QRect effectiveWidgetRect(const QWidget *w)
{
    // based on QWidgetPrivate::effectiveRectFor
#if QT_CONFIG(graphicseffect)
    if (auto graphicsEffect = w->graphicsEffect(); graphicsEffect && graphicsEffect->isEnabled())
        return graphicsEffect->boundingRectFor(w->rect()).toAlignedRect();
#endif // QT_CONFIG(graphicseffect)
    return w->rect();
}

static QRect clipRect(const QWidget *w)
{
    // based on QWidgetPrivate::clipRect
    if (!w->isVisible()) {
        return QRect();
    }
    QRect r = effectiveWidgetRect(w);
    int ox = 0;
    int oy = 0;
    while (w && w->isVisible() && !w->isWindow() && w->parentWidget()) {
        ox -= w->x();
        oy -= w->y();
        w = w->parentWidget();
        r &= QRect(ox, oy, w->width(), w->height());
    }
    return r;
}

void FocusFrame::paintEvent(QPaintEvent *)
{
    if (!widget()) {
        return;
    }

    QStylePainter p(this);
    QStyleOptionFocusRect option;
    initStyleOption(&option);
    const int vmargin = style()->pixelMetric(QStyle::PM_FocusFrameVMargin, &option);
    const int hmargin = style()->pixelMetric(QStyle::PM_FocusFrameHMargin, &option);
    const QRect rect = clipRect(widget()).adjusted(0, 0, hmargin * 2, vmargin * 2);
    p.setClipRect(rect);
    p.drawPrimitive(QStyle::PE_FrameFocusRect, option);
}
}

class KleopatraApplication::Private
{
    friend class ::KleopatraApplication;
    KleopatraApplication *const q;

public:
    explicit Private(KleopatraApplication *qq)
        : q(qq)
        , ignoreNewInstance(true)
        , firstNewInstance(true)
#ifndef QT_NO_SYSTEMTRAYICON
        , sysTray(nullptr)
#endif
    {
    }
    ~Private()
    {
#ifndef QT_NO_SYSTEMTRAYICON
        delete sysTray;
#endif
    }
    void setUpSysTrayIcon()
    {
#ifndef QT_NO_SYSTEMTRAYICON
        Q_ASSERT(readerStatus);
        sysTray = new SysTrayIcon();
        sysTray->setFirstCardWithNullPin(readerStatus->firstCardWithNullPin());
        connect(readerStatus.get(), &SmartCard::ReaderStatus::firstCardWithNullPinChanged, sysTray, &SysTrayIcon::setFirstCardWithNullPin);
#endif
    }

private:
    void connectConfigureDialog()
    {
        if (configureDialog) {
            if (q->mainWindow()) {
                connect(configureDialog, SIGNAL(configCommitted()), q->mainWindow(), SLOT(slotConfigCommitted()));
            }
            connect(configureDialog, &ConfigureDialog::configCommitted, q, &KleopatraApplication::configurationChanged);
        }
    }
    void disconnectConfigureDialog()
    {
        if (configureDialog) {
            if (q->mainWindow()) {
                disconnect(configureDialog, SIGNAL(configCommitted()), q->mainWindow(), SLOT(slotConfigCommitted()));
            }
            disconnect(configureDialog, &ConfigureDialog::configCommitted, q, &KleopatraApplication::configurationChanged);
        }
    }

public:
    bool ignoreNewInstance;
    bool firstNewInstance;
    QPointer<FocusFrame> focusFrame;
    QPointer<ConfigureDialog> configureDialog;
    QPointer<GroupsConfigDialog> groupsConfigDialog;
    QPointer<MainWindow> mainWindow;
    std::unique_ptr<SmartCard::ReaderStatus> readerStatus;
#ifndef QT_NO_SYSTEMTRAYICON
    SysTrayIcon *sysTray;
#endif
    std::shared_ptr<KeyGroupConfig> groupConfig;
    std::shared_ptr<KeyCache> keyCache;
    std::shared_ptr<Log> log;
    std::shared_ptr<FileSystemWatcher> watcher;
    std::shared_ptr<QSettings> distroSettings;

public:
    void setupKeyCache()
    {
        keyCache = KeyCache::mutableInstance();
        keyCache->setRefreshInterval(SMimeValidationPreferences{}.refreshInterval());
        watcher.reset(new FileSystemWatcher);

        watcher->whitelistFiles(gnupgFileWhitelist());
        watcher->addPaths(gnupgFolderWhitelist());
        watcher->setDelay(1000);
        keyCache->addFileSystemWatcher(watcher);
        keyCache->setGroupConfig(groupConfig);
        keyCache->setGroupsEnabled(Settings().groupsEnabled());
        // always enable remarks (aka tags); in particular, this triggers a
        // relisting of the keys with signatures and signature notations
        // after the initial (fast) key listing
        keyCache->enableRemarks(true);
    }

    void setUpFilterManager()
    {
        if (!Settings{}.cmsEnabled()) {
            KeyFilterManager::instance()->alwaysFilterByProtocol(GpgME::OpenPGP);
        }
    }

    void setupLogging()
    {
        log = Log::mutableInstance();

        const QByteArray envOptions = qgetenv("KLEOPATRA_LOGOPTIONS");
        const bool logAll = envOptions.trimmed() == "all";
        const QList<QByteArray> options = envOptions.isEmpty() ? default_logging_options() : envOptions.split(',');

        const QByteArray dirNative = qgetenv("KLEOPATRA_LOGDIR");
        if (dirNative.isEmpty()) {
            return;
        }
        const QString dir = QFile::decodeName(dirNative);
        const QString logFileName = QDir(dir).absoluteFilePath(QStringLiteral("kleopatra.log.%1").arg(QCoreApplication::applicationPid()));
        std::unique_ptr<QFile> logFile(new QFile(logFileName));
        if (!logFile->open(QIODevice::WriteOnly | QIODevice::Append)) {
            qCDebug(KLEOPATRA_LOG) << "Could not open file for logging: " << logFileName << "\nLogging disabled";
            return;
        }

        log->setOutputDirectory(dir);
        if (logAll || options.contains("io")) {
            log->setIOLoggingEnabled(true);
        }
        qInstallMessageHandler(Log::messageHandler);

        if (logAll || options.contains("pipeio")) {
            KDPipeIODevice::setDebugLevel(KDPipeIODevice::Debug);
        }
        UiServer::setLogStream(log->logFile());
    }

    void updateFocusFrame(QWidget *focusWidget)
    {
        if (focusWidget && focusWidget->inherits("QLabel") && focusWidget->window()->testAttribute(Qt::WA_KeyboardFocusChange)) {
            if (!focusFrame) {
                focusFrame = new FocusFrame{focusWidget};
            }
            focusFrame->setWidget(focusWidget);
        } else if (focusFrame) {
            focusFrame->setWidget(nullptr);
        }
    }
};

KleopatraApplication::KleopatraApplication(int &argc, char *argv[])
    : QApplication(argc, argv)
    , d(new Private(this))
{
    // disable parent<->child navigation in tree views with left/right arrow keys
    // because this interferes with column by column navigation that is required
    // for accessibility
    setStyleSheet(QStringLiteral("QTreeView { arrow-keys-navigate-into-children: 0; }"));
#ifdef Q_OS_WIN
    if (SystemInfo::isHighContrastModeActive()) {
        // use colors specified by Windows if high-contrast mode is active
        QPalette highContrastPalette = palette();

        const QColor linkColor = win_getSysColor(COLOR_HOTLIGHT);
        highContrastPalette.setColor(QPalette::All, QPalette::Link, linkColor);
        highContrastPalette.setColor(QPalette::All, QPalette::LinkVisited, linkColor);

        const QColor disabledColor = win_getSysColor(COLOR_GRAYTEXT);
        highContrastPalette.setColor(QPalette::Disabled, QPalette::WindowText, disabledColor);
        highContrastPalette.setColor(QPalette::Disabled, QPalette::Text, disabledColor);
        highContrastPalette.setColor(QPalette::Disabled, QPalette::ButtonText, disabledColor);
        highContrastPalette.setColor(QPalette::All, QPalette::PlaceholderText, disabledColor);

        setPalette(highContrastPalette);
    }
#endif
    connect(this, &QApplication::focusChanged, this, [this](QWidget *, QWidget *now) {
        d->updateFocusFrame(now);
    });
}

void KleopatraApplication::init()
{
    const QString groupConfigPath = Kleo::gnupgHomeDirectory() + QLatin1String("/kleopatra/kleopatragroupsrc");
    d->groupConfig = std::make_shared<KeyGroupConfig>(groupConfigPath);

#ifdef Q_OS_WIN
    QWindowsWindowFunctions::setWindowActivationBehavior(QWindowsWindowFunctions::AlwaysActivateWindow);
#endif
    const auto blockedUrlSchemes = Settings{}.blockedUrlSchemes();
    for (const auto &scheme : blockedUrlSchemes) {
        QDesktopServices::setUrlHandler(scheme, this, "blockUrl");
    }
    add_resources();
    DN::setAttributeOrder(Settings{}.attributeOrder());
    /* Start the gpg-agent early, this is done explicitly
     * because on an empty keyring our keylistings wont start
     * the agent. In that case any assuan-connect calls to
     * the agent will fail. The requested start via the
     * connection is additionally done in case the gpg-agent
     * is killed while Kleopatra is running. */
    startGpgAgent();
    d->readerStatus.reset(new SmartCard::ReaderStatus);
    connect(d->readerStatus.get(), &SmartCard::ReaderStatus::startOfGpgAgentRequested, this, &KleopatraApplication::startGpgAgent);
    d->setupKeyCache();
    d->setUpSysTrayIcon();
    d->setUpFilterManager();
    d->setupLogging();
#ifdef Q_OS_WIN
    if (!SystemInfo::isHighContrastModeActive()) {
        /* In high contrast mode we do not want our own colors */
        new KColorSchemeManager(this);
    }
#else
    new KColorSchemeManager(this);
#endif

#ifndef QT_NO_SYSTEMTRAYICON
    if (d->sysTray) {
        d->sysTray->show();
    }
#endif
    if (!Kleo::userIsElevated()) {
        // For users running Kleo with elevated permissions on Windows we
        // always quit the application when the last window is closed.
        setQuitOnLastWindowClosed(false);
    }

    // Sync config when we are about to quit
    connect(this, &QApplication::aboutToQuit, this, []() {
        KSharedConfig::openConfig()->sync();
    });
}

KleopatraApplication::~KleopatraApplication()
{
    delete d->groupsConfigDialog;
    delete d->mainWindow;
}

namespace
{
using Func = void (KleopatraApplication::*)(const QStringList &, GpgME::Protocol);
}

void KleopatraApplication::slotActivateRequested(const QStringList &arguments, const QString &workingDirectory)
{
    QCommandLineParser parser;

    kleopatra_options(&parser);
    QString err;
    if (!arguments.isEmpty() && !parser.parse(arguments)) {
        err = parser.errorText();
    } else if (arguments.isEmpty()) {
        // KDBusServices omits the application name if no other
        // arguments are provided. In that case the parser prints
        // a warning.
        parser.parse(QStringList() << QCoreApplication::applicationFilePath());
    }

    if (err.isEmpty()) {
        err = newInstance(parser, workingDirectory);
    }

    if (!err.isEmpty()) {
        KMessageBox::error(nullptr, err.toHtmlEscaped(), i18n("Failed to execute command"));
        Q_EMIT setExitValue(1);
        return;
    }
    Q_EMIT setExitValue(0);
}

QString KleopatraApplication::newInstance(const QCommandLineParser &parser, const QString &workingDirectory)
{
    if (d->ignoreNewInstance) {
        qCDebug(KLEOPATRA_LOG) << "New instance ignored because of ignoreNewInstance";
        return QString();
    }

    QStringList files;
    const QDir cwd = QDir(workingDirectory);
    bool queryMode = parser.isSet(QStringLiteral("query")) || parser.isSet(QStringLiteral("search"));

    // Query and Search treat positional arguments differently, see below.
    if (!queryMode) {
        const auto positionalArguments = parser.positionalArguments();
        for (const QString &file : positionalArguments) {
            // We do not check that file exists here. Better handle
            // these errors in the UI.
            if (QFileInfo(file).isAbsolute()) {
                files << file;
            } else {
                files << cwd.absoluteFilePath(file);
            }
        }
    }

    GpgME::Protocol protocol = GpgME::UnknownProtocol;

    if (parser.isSet(QStringLiteral("openpgp"))) {
        qCDebug(KLEOPATRA_LOG) << "found OpenPGP";
        protocol = GpgME::OpenPGP;
    }

    if (parser.isSet(QStringLiteral("cms"))) {
        qCDebug(KLEOPATRA_LOG) << "found CMS";
        if (protocol == GpgME::OpenPGP) {
            return i18n("Ambiguous protocol: --openpgp and --cms");
        }
        protocol = GpgME::CMS;
    }

    // Check for Parent Window id
    WId parentId = 0;
    if (parser.isSet(QStringLiteral("parent-windowid"))) {
#ifdef Q_OS_WIN
        // WId is not a portable type as it is a pointer type on Windows.
        // casting it from an integer is ok though as the values are guaranteed to
        // be compatible in the documentation.
        parentId = reinterpret_cast<WId>(parser.value(QStringLiteral("parent-windowid")).toUInt());
#else
        parentId = parser.value(QStringLiteral("parent-windowid")).toUInt();
#endif
    }

    // Handle openpgp4fpr URI scheme
    QString needle;
    if (queryMode) {
        needle = parser.positionalArguments().join(QLatin1Char(' '));
    }
    if (needle.startsWith(QLatin1String("openpgp4fpr:"))) {
        needle.remove(0, 12);
    }

    // Check for --search command.
    if (parser.isSet(QStringLiteral("search"))) {
        // This is an extra command instead of a combination with the
        // similar query to avoid changing the older query commands behavior
        // and query's "show details if a certificate exist or search on a
        // keyserver" logic is hard to explain and use consistently.
        if (needle.isEmpty()) {
            return i18n("No search string specified for --search");
        }
        auto const cmd = new LookupCertificatesCommand(needle, nullptr);
        cmd->setParentWId(parentId);
        cmd->start();
        return QString();
    }

    // Check for --query command
    if (parser.isSet(QStringLiteral("query"))) {
        if (needle.isEmpty()) {
            return i18n("No fingerprint argument specified for --query");
        }
        auto cmd = Command::commandForQuery(needle);
        cmd->setParentWId(parentId);
        cmd->start();
        return QString();
    }

    // Check for --gen-key command
    if (parser.isSet(QStringLiteral("gen-key"))) {
        if (protocol == GpgME::CMS) {
            const Kleo::Settings settings{};
            if (settings.cmsEnabled() && settings.cmsCertificateCreationAllowed()) {
                auto cmd = new NewCertificateSigningRequestCommand;
                cmd->setParentWId(parentId);
                cmd->start();
            } else {
                return i18n("You are not allowed to create S/MIME certificate signing requests.");
            }
        } else {
            auto cmd = new NewOpenPGPCertificateCommand;
            cmd->setParentWId(parentId);
            cmd->start();
        }
        return QString();
    }

    // Check for --config command
    if (parser.isSet(QStringLiteral("config"))) {
        openConfigDialogWithForeignParent(parentId);
        return QString();
    }

    struct FuncInfo {
        QString optionName;
        Func func;
    };

    // While most of these options can be handled by the content autodetection
    // below it might be useful to override the autodetection if the input is in
    // doubt and you e.g. only want to import .asc files or fail and not decrypt them
    // if they are actually encrypted data.
    static const std::vector<FuncInfo> funcMap{
        {QStringLiteral("import-certificate"), &KleopatraApplication::importCertificatesFromFile},
        {QStringLiteral("encrypt"), &KleopatraApplication::encryptFiles},
        {QStringLiteral("sign"), &KleopatraApplication::signFiles},
        {QStringLiteral("encrypt-sign"), &KleopatraApplication::signEncryptFiles},
        {QStringLiteral("sign-encrypt"), &KleopatraApplication::signEncryptFiles},
        {QStringLiteral("decrypt"), &KleopatraApplication::decryptFiles},
        {QStringLiteral("verify"), &KleopatraApplication::verifyFiles},
        {QStringLiteral("decrypt-verify"), &KleopatraApplication::decryptVerifyFiles},
        {QStringLiteral("checksum"), &KleopatraApplication::checksumFiles},
    };

    QString found;
    Func foundFunc = nullptr;
    for (const auto &[opt, fn] : funcMap) {
        if (parser.isSet(opt) && found.isEmpty()) {
            found = opt;
            foundFunc = fn;
        } else if (parser.isSet(opt)) {
            return i18n(R"(Ambiguous commands "%1" and "%2")", found, opt);
        }
    }

    QStringList errors;
    if (!found.isEmpty()) {
        if (files.empty()) {
            return i18n("No files specified for \"%1\" command", found);
        }
        qCDebug(KLEOPATRA_LOG) << "found" << found;
        (this->*foundFunc)(files, protocol);
    } else {
        if (files.empty()) {
            if (!(d->firstNewInstance && isSessionRestored())) {
                qCDebug(KLEOPATRA_LOG) << "openOrRaiseMainWindow";
                openOrRaiseMainWindow();
            }
        } else {
            for (const QString &fileName : std::as_const(files)) {
                QFileInfo fi(fileName);
                if (!fi.isReadable()) {
                    errors << i18n("Cannot read \"%1\"", fileName);
                }
            }
            handleFiles(files, parentId);
        }
    }
    d->firstNewInstance = false;

#ifdef Q_OS_WIN
    // On Windows we might be started from the
    // explorer in any working directory. E.g.
    // a double click on a file. To avoid preventing
    // the folder from deletion we set the
    // working directory to the users homedir.
    QDir::setCurrent(QDir::homePath());
#endif

    return errors.join(QLatin1Char('\n'));
}

void KleopatraApplication::handleFiles(const QStringList &files, WId parentId)
{
    auto mw = mainWindow();
    if (!mw) {
        mw = new MainWindow;
        mw->setAttribute(Qt::WA_DeleteOnClose);
        setMainWindow(mw);
        d->connectConfigureDialog();
    }
    const QVector<Command *> allCmds = Command::commandsForFiles(files, mw->keyListController());
    for (Command *cmd : allCmds) {
        if (parentId) {
            cmd->setParentWId(parentId);
        } else {
            cmd->setParentWidget(mw);
        }
        if (dynamic_cast<ImportCertificateFromFileCommand *>(cmd)) {
            openOrRaiseMainWindow();
        }
        cmd->start();
    }
}

const MainWindow *KleopatraApplication::mainWindow() const
{
    return d->mainWindow;
}

MainWindow *KleopatraApplication::mainWindow()
{
    return d->mainWindow;
}

void KleopatraApplication::setMainWindow(MainWindow *mainWindow)
{
    if (mainWindow == d->mainWindow) {
        return;
    }

    d->disconnectConfigureDialog();

    d->mainWindow = mainWindow;
#ifndef QT_NO_SYSTEMTRAYICON
    if (d->sysTray) {
        d->sysTray->setMainWindow(mainWindow);
    }
#endif

    d->connectConfigureDialog();
}

static void open_or_raise(QWidget *w)
{
#ifdef Q_OS_WIN
    if (w->isMinimized()) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "unminimizing and raising window";
        w->raise();
    } else if (w->isVisible()) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "raising window";
        w->raise();
#else
    if (w->isVisible()) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "activating window";
        KWindowSystem::updateStartupId(w->windowHandle());
        KWindowSystem::activateWindow(w->windowHandle());
#endif
    } else {
        qCDebug(KLEOPATRA_LOG) << __func__ << "showing window";
        w->show();
    }
}

void KleopatraApplication::toggleMainWindowVisibility()
{
    if (mainWindow()) {
        mainWindow()->setVisible(!mainWindow()->isVisible());
    } else {
        openOrRaiseMainWindow();
    }
}

void KleopatraApplication::restoreMainWindow()
{
    qCDebug(KLEOPATRA_LOG) << "restoring main window";

    // Sanity checks
    if (!isSessionRestored()) {
        qCDebug(KLEOPATRA_LOG) << "Not in session restore";
        return;
    }

    if (mainWindow()) {
        qCDebug(KLEOPATRA_LOG) << "Already have main window";
        return;
    }

    auto mw = new MainWindow;
    if (KMainWindow::canBeRestored(1)) {
        // restore to hidden state, Mainwindow::readProperties() will
        // restore saved visibility.
        mw->restore(1, false);
    }

    mw->setAttribute(Qt::WA_DeleteOnClose);
    setMainWindow(mw);
    d->connectConfigureDialog();
}

void KleopatraApplication::openOrRaiseMainWindow()
{
    MainWindow *mw = mainWindow();
    if (!mw) {
        mw = new MainWindow;
        mw->setAttribute(Qt::WA_DeleteOnClose);
        setMainWindow(mw);
        d->connectConfigureDialog();
    }
    open_or_raise(mw);
    UpdateNotification::checkUpdate(mw);
}

void KleopatraApplication::openConfigDialogWithForeignParent(WId parentWId)
{
    if (!d->configureDialog) {
        d->configureDialog = new ConfigureDialog;
        d->configureDialog->setAttribute(Qt::WA_DeleteOnClose);
        d->connectConfigureDialog();
    }

    // This is similar to what the commands do.
    if (parentWId) {
        if (QWidget *pw = QWidget::find(parentWId)) {
            d->configureDialog->setParent(pw, d->configureDialog->windowFlags());
        } else {
            d->configureDialog->setAttribute(Qt::WA_NativeWindow, true);
            KWindowSystem::setMainWindow(d->configureDialog->windowHandle(), parentWId);
        }
    }

    open_or_raise(d->configureDialog);

    // If we have a parent we want to raise over it.
    if (parentWId) {
        d->configureDialog->raise();
    }
}

void KleopatraApplication::openOrRaiseConfigDialog()
{
    openConfigDialogWithForeignParent(0);
}

void KleopatraApplication::openOrRaiseGroupsConfigDialog(QWidget *parent)
{
    if (!d->groupsConfigDialog) {
        d->groupsConfigDialog = new GroupsConfigDialog{parent};
        d->groupsConfigDialog->setAttribute(Qt::WA_DeleteOnClose);
    } else {
        // reparent the dialog to ensure it's shown on top of the (modal) parent
        d->groupsConfigDialog->setParent(parent, Qt::Dialog);
    }
    open_or_raise(d->groupsConfigDialog);
}

#ifndef QT_NO_SYSTEMTRAYICON
void KleopatraApplication::startMonitoringSmartCard()
{
    Q_ASSERT(d->readerStatus);
    d->readerStatus->startMonitoring();
}
#endif // QT_NO_SYSTEMTRAYICON

void KleopatraApplication::importCertificatesFromFile(const QStringList &files, GpgME::Protocol /*proto*/)
{
    openOrRaiseMainWindow();
    if (!files.empty()) {
        mainWindow()->importCertificatesFromFile(files);
    }
}

void KleopatraApplication::encryptFiles(const QStringList &files, GpgME::Protocol proto)
{
    auto const cmd = new SignEncryptFilesCommand(files, nullptr);
    cmd->setEncryptionPolicy(Force);
    cmd->setSigningPolicy(Allow);
    if (proto != GpgME::UnknownProtocol) {
        cmd->setProtocol(proto);
    }
    cmd->start();
}

void KleopatraApplication::signFiles(const QStringList &files, GpgME::Protocol proto)
{
    auto const cmd = new SignEncryptFilesCommand(files, nullptr);
    cmd->setSigningPolicy(Force);
    cmd->setEncryptionPolicy(Deny);
    if (proto != GpgME::UnknownProtocol) {
        cmd->setProtocol(proto);
    }
    cmd->start();
}

void KleopatraApplication::signEncryptFiles(const QStringList &files, GpgME::Protocol proto)
{
    auto const cmd = new SignEncryptFilesCommand(files, nullptr);
    if (proto != GpgME::UnknownProtocol) {
        cmd->setProtocol(proto);
    }
    cmd->start();
}

void KleopatraApplication::decryptFiles(const QStringList &files, GpgME::Protocol /*proto*/)
{
    auto const cmd = new DecryptVerifyFilesCommand(files, nullptr);
    cmd->setOperation(Decrypt);
    cmd->start();
}

void KleopatraApplication::verifyFiles(const QStringList &files, GpgME::Protocol /*proto*/)
{
    auto const cmd = new DecryptVerifyFilesCommand(files, nullptr);
    cmd->setOperation(Verify);
    cmd->start();
}

void KleopatraApplication::decryptVerifyFiles(const QStringList &files, GpgME::Protocol /*proto*/)
{
    auto const cmd = new DecryptVerifyFilesCommand(files, nullptr);
    cmd->start();
}

void KleopatraApplication::checksumFiles(const QStringList &files, GpgME::Protocol /*proto*/)
{
    QStringList verifyFiles, createFiles;

    for (const QString &file : files) {
        if (isChecksumFile(file)) {
            verifyFiles << file;
        } else {
            createFiles << file;
        }
    }

    if (!verifyFiles.isEmpty()) {
        auto const cmd = new ChecksumVerifyFilesCommand(verifyFiles, nullptr);
        cmd->start();
    }
    if (!createFiles.isEmpty()) {
        auto const cmd = new ChecksumCreateFilesCommand(createFiles, nullptr);
        cmd->start();
    }
}

void KleopatraApplication::setIgnoreNewInstance(bool ignore)
{
    d->ignoreNewInstance = ignore;
}

bool KleopatraApplication::ignoreNewInstance() const
{
    return d->ignoreNewInstance;
}

void KleopatraApplication::blockUrl(const QUrl &url)
{
    qCDebug(KLEOPATRA_LOG) << "Blocking URL" << url;
    KMessageBox::error(mainWindow(), i18n("Opening an external link is administratively prohibited."), i18n("Prohibited"));
}

void KleopatraApplication::startGpgAgent()
{
    Kleo::launchGpgAgent();
}

void KleopatraApplication::setDistributionSettings(const std::shared_ptr<QSettings> &settings)
{
    d->distroSettings = settings;
}

std::shared_ptr<QSettings> KleopatraApplication::distributionSettings() const
{
    return d->distroSettings;
}

#include "kleopatraapplication.moc"
