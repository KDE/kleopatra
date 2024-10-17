/*
    main.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004, 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "aboutdata.h"
#include "kleopatraapplication.h"
#include "mainwindow.h"
#include "utils/migration.h"

#include "accessibility/accessiblewidgetfactory.h"

#include <commands/reloadkeyscommand.h>
#include <commands/selftestcommand.h>

#ifdef Q_OS_WIN
#include "conf/kmessageboxdontaskagainstorage.h"
#endif
#include "utils/kuniqueservice.h"
#include "utils/userinfo.h"
#include <Libkleo/GnuPG>
#include <utils/archivedefinition.h>

#include <uiserver/assuancommand.h>
#include <uiserver/createchecksumscommand.h>
#include <uiserver/decryptcommand.h>
#include <uiserver/decryptfilescommand.h>
#include <uiserver/decryptverifyfilescommand.h>
#include <uiserver/echocommand.h>
#include <uiserver/encryptcommand.h>
#include <uiserver/importfilescommand.h>
#include <uiserver/prepencryptcommand.h>
#include <uiserver/prepsigncommand.h>
#include <uiserver/selectcertificatecommand.h>
#include <uiserver/signcommand.h>
#include <uiserver/signencryptfilescommand.h>
#include <uiserver/uiserver.h>
#include <uiserver/verifychecksumscommand.h>
#include <uiserver/verifycommand.h>
#include <uiserver/verifyfilescommand.h>

#include <Libkleo/ChecksumDefinition>

#include "kleopatra_debug.h"
#include "kleopatra_options.h"

#include <KCrash>
#include <KLocalizedString>
#include <KMessageBox>

#include <QAccessible>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QMessageBox>
#include <QThreadPool>
#include <QTime>
#include <QTimer>

#include <gpgme++/error.h>
#include <gpgme++/global.h>

#include <QCommandLineParser>
#include <iostream>
#include <memory>

QElapsedTimer startupTimer;

static bool selfCheck()
{
    Kleo::Commands::SelfTestCommand cmd(nullptr);
    cmd.setAutoDelete(false);
    cmd.setAutomaticMode(true);
    QEventLoop loop;
    QObject::connect(&cmd, &Kleo::Commands::SelfTestCommand::finished, &loop, &QEventLoop::quit);
    QTimer::singleShot(0, &cmd, &Kleo::Command::start); // start() may Q_EMIT finished()...
    loop.exec();
    if (cmd.isCanceled()) {
        return false;
    } else {
        return true;
    }
}

static void fillKeyCache(Kleo::UiServer *server)
{
    auto cmd = new Kleo::ReloadKeysCommand(nullptr);
    QObject::connect(cmd, SIGNAL(finished()), server, SLOT(enableCryptoCommands()));
    cmd->start();
}

int main(int argc, char **argv)
{
    startupTimer.start();

    KleopatraApplication app(argc, argv);
    // Set OrganizationDomain early as this is used to generate the service
    // name that will be registered on the bus.
    app.setOrganizationDomain(QStringLiteral("kde.org"));

    STARTUP_TIMING << "Application created";
    /* Create the unique service ASAP to prevent double starts if
     * the application is started twice very quickly. */
    KUniqueService service;
    QObject::connect(&service, &KUniqueService::activateRequested, &app, &KleopatraApplication::slotActivateRequested);
    QObject::connect(&app, &KleopatraApplication::setExitValue, &service, [&service](int i) {
        service.setExitValue(i);
    });
    STARTUP_TIMING << "Service created";

    QAccessible::installFactory(Kleo::accessibleWidgetFactory);
    qCDebug(KLEOPATRA_LOG) << "Application created";

    app.setWindowIcon(QIcon::fromTheme(QStringLiteral("kleopatra"), app.windowIcon()));

    KLocalizedString::setApplicationDomain(QByteArrayLiteral("kleopatra"));

    // Initialize GpgME
    {
        const GpgME::Error gpgmeInitError = GpgME::initializeLibrary(0);
        if (gpgmeInitError) {
            KMessageBox::error(nullptr,
                               xi18nc("@info",
                                      "<para>The version of the <application>GpgME</application> library you are running against "
                                      "is older than the one that the <application>GpgME++</application> library was built against.</para>"
                                      "<para><application>Kleopatra</application> will not function in this setting.</para>"
                                      "<para>Please ask your administrator for help in resolving this issue.</para>"),
                               i18nc("@title", "GpgME Too Old"));
            return EXIT_FAILURE;
        }
        STARTUP_TIMING << "GPGME Initialized";
    }

    AboutData aboutData;
    KAboutData::setApplicationData(aboutData);

    KCrash::initialize();

    if (Kleo::userIsElevated()) {
        /* This is a safeguard against bugreports that something fails because
         * of permission problems on windows.  Some users still have the Windows
         * Vista behavior of running things as Administrator.  This can break
         * GnuPG in horrible ways for example if a stale lockfile is left that
         * can't be removed without another elevation.
         *
         * Note: This is not the same as running as root on Linux. Elevated means
         * that you are temporarily running with the "normal" user environment but
         * with elevated permissions.
         * */
        if (KMessageBox::warningContinueCancel(nullptr,
                                               xi18nc("@info",
                                                      "<para><application>Kleopatra</application> cannot be run as adminstrator without "
                                                      "breaking file permissions in the GnuPG data folder.</para>"
                                                      "<para>To manage keys for other users please manage them as a normal user and "
                                                      "copy the <filename>AppData\\Roaming\\gnupg</filename> directory with proper permissions.</para>")
                                                   + xi18nc("@info", "<para>Are you sure that you want to continue?</para>"),
                                               i18nc("@title", "Running as Administrator"))
            != KMessageBox::Continue) {
            return EXIT_FAILURE;
        }
        qCWarning(KLEOPATRA_LOG) << "User is running with administrative permissions.";
    }
    // Delay init after KUniqueservice call as this might already
    // have terminated us and so we can avoid overhead (e.g. keycache
    // setup / systray icon).
    Migration::migrate();
    app.init();
    STARTUP_TIMING << "Application initialized";

    QCommandLineParser parser;
    aboutData.setupCommandLine(&parser);
    kleopatra_options(&parser);

    parser.process(QApplication::arguments());
    aboutData.processCommandLine(&parser);
    {
        const unsigned int threads = QThreadPool::globalInstance()->maxThreadCount();
        QThreadPool::globalInstance()->setMaxThreadCount(qMax(2U, threads));
    }

    Kleo::ChecksumDefinition::setInstallPath(Kleo::gpg4winInstallPath());
    Kleo::ArchiveDefinition::setInstallPath(Kleo::gnupgInstallPath());

#ifndef DISABLE_UISERVER
    int rc;
    Kleo::UiServer *server = nullptr;
    try {
        server = new Kleo::UiServer(parser.value(QStringLiteral("uiserver-socket")));
        STARTUP_TIMING << "UiServer created";

        QObject::connect(server, &Kleo::UiServer::startKeyManagerRequested, &app, &KleopatraApplication::openOrRaiseMainWindow);

        QObject::connect(server, &Kleo::UiServer::startConfigDialogRequested, &app, &KleopatraApplication::openOrRaiseConfigDialog);

#define REGISTER(Command) server->registerCommandFactory(std::shared_ptr<Kleo::AssuanCommandFactory>(new Kleo::GenericAssuanCommandFactory<Kleo::Command>))
        REGISTER(CreateChecksumsCommand);
        REGISTER(DecryptCommand);
        REGISTER(DecryptFilesCommand);
        REGISTER(DecryptVerifyFilesCommand);
        REGISTER(EchoCommand);
        REGISTER(EncryptCommand);
        REGISTER(EncryptFilesCommand);
        REGISTER(EncryptSignFilesCommand);
        REGISTER(ImportFilesCommand);
        REGISTER(PrepEncryptCommand);
        REGISTER(PrepSignCommand);
        REGISTER(SelectCertificateCommand);
        REGISTER(SignCommand);
        REGISTER(SignEncryptFilesCommand);
        REGISTER(SignFilesCommand);
        REGISTER(VerifyChecksumsCommand);
        REGISTER(VerifyCommand);
        REGISTER(VerifyFilesCommand);
#undef REGISTER

        server->start();
        STARTUP_TIMING << "UiServer started";
    } catch (const std::exception &e) {
        qCDebug(KLEOPATRA_LOG) << "Failed to start UI Server: " << e.what();
#ifdef Q_OS_WIN
        // We should probably change the UIServer to be only run on Windows at all because
        // only the Windows Explorer Plugin uses it. But the plan of GnuPG devs as of 2022 is to
        // change the Windows Explorer Plugin to use the command line and then remove the
        // UiServer for everyone.
        QMessageBox::information(nullptr,
                                 i18n("GPG UI Server Error"),
                                 i18nc("This error message is only shown on Windows when the socket to communicate with "
                                       "Windows Explorer could not be created. This often times means that the whole installation is "
                                       "buggy. e.g. GnuPG is not installed at all.",
                                       "<qt>The Kleopatra Windows Explorer Module could not be initialized.<br/>"
                                       "The error given was: <b>%1</b><br/>"
                                       "This likely means that there is a problem with your installation. Try reinstalling or "
                                       "contact your Administrator for support.<br/>"
                                       "You can try to continue to use Kleopatra but there might be other problems.</qt>",
                                       QString::fromUtf8(e.what()).toHtmlEscaped()));
#endif
    }
#endif // DISABLE_UISERVER
    const bool daemon = parser.isSet(QStringLiteral("daemon"));
    if (!daemon && app.isSessionRestored()) {
        app.restoreMainWindow();
    }

    if (!selfCheck()) {
        return EXIT_FAILURE;
    }
    STARTUP_TIMING << "SelfCheck completed";

    if (server) {
        fillKeyCache(server);
    }
#ifndef QT_NO_SYSTEMTRAYICON
    app.startMonitoringSmartCard();
#endif
    app.setIgnoreNewInstance(false);

    if (!daemon) {
        const QString err = app.newInstance(parser);
        if (!err.isEmpty()) {
            std::cerr << i18n("Invalid arguments: %1", err).toLocal8Bit().constData() << "\n";
            return EXIT_FAILURE;
        }
        STARTUP_TIMING << "new instance created";
    }

#ifdef Q_OS_WIN
    auto messageBoxConfigStorage = std::make_unique<KMessageBoxDontAskAgainConfigStorage>();
    KMessageBox::setDontShowAgainInterface(messageBoxConfigStorage.get());
#endif

    rc = app.exec();

    app.setIgnoreNewInstance(true);
    QObject::disconnect(server, &Kleo::UiServer::startKeyManagerRequested, &app, &KleopatraApplication::openOrRaiseMainWindow);
    QObject::disconnect(server, &Kleo::UiServer::startConfigDialogRequested, &app, &KleopatraApplication::openOrRaiseConfigDialog);

    if (server) {
        server->stop();
        server->waitForStopped();
        delete server;
    }

    return rc;
}
