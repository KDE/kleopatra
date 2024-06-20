/*
    kleopatraapplication.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QApplication>
#include <QCommandLineParser>
#include <QElapsedTimer>

#include <gpgme++/global.h>

#include <memory>

extern QElapsedTimer startupTimer;
#define STARTUP_TIMING qCDebug(KLEOPATRA_LOG) << "Startup timing:" << startupTimer.elapsed() << "ms:"
#define STARTUP_TRACE qCDebug(KLEOPATRA_LOG) << "Startup timing:" << startupTimer.elapsed() << "ms:" << SRCNAME << __func__ << __LINE__;

class MainWindow;
class SysTrayIcon;
class QSettings;

class KleopatraApplication : public QApplication
{
    Q_OBJECT
public:
    /** Create a new Application object. You have to
     * make sure to call init afterwards to get a valid object.
     * This is to delay initialisation after the UniqueService
     * call is done and our init / call might be forwarded to
     * another instance. */
    KleopatraApplication(int &argc, char *argv[]);
    ~KleopatraApplication() override;

    /** Initialize the application. Without calling init any
     * other call to KleopatraApplication will result in undefined behavior
     * and likely crash. */
    void init();

    static KleopatraApplication *instance()
    {
        return qobject_cast<KleopatraApplication *>(qApp);
    }

    /** Starts a new instance or a command from the command line.
     *
     * Handles the parser options and starts the according commands.
     * If ignoreNewInstance is set this function does nothing.
     * The parser should have been initialized with kleopatra_options and
     * already processed.
     * If kleopatra is not session restored
     *
     * @param parser: The command line parser to use.
     * @param workingDirectory: Optional working directory for file arguments.
     *
     * @returns an empty QString on success. A localized error message otherwise.
     * */
    QString newInstance(const QCommandLineParser &parser, const QString &workingDirectory = QString());

    void setMainWindow(MainWindow *mw);

    const MainWindow *mainWindow() const;
    MainWindow *mainWindow();

    void setIgnoreNewInstance(bool on);
    bool ignoreNewInstance() const;
    void toggleMainWindowVisibility();
    void restoreMainWindow();
    void openConfigDialogWithForeignParent(WId parentWId);

    /* Add optional signed settings for specialized distributions */
    void setDistributionSettings(const std::shared_ptr<QSettings> &settings);
    std::shared_ptr<QSettings> distributionSettings() const;

public Q_SLOTS:
    void openOrRaiseMainWindow();
    void openOrRaiseSmartCardWindow();
    void openOrRaiseConfigDialog();
    void openOrRaiseGroupsConfigDialog(QWidget *parent);
#ifndef QT_NO_SYSTEMTRAYICON
    void startMonitoringSmartCard();
#endif
    void importCertificatesFromFile(const QStringList &files, GpgME::Protocol proto);
    void encryptFiles(const QStringList &files, GpgME::Protocol proto);
    void signFiles(const QStringList &files, GpgME::Protocol proto);
    void signEncryptFiles(const QStringList &files, GpgME::Protocol proto);
    void decryptFiles(const QStringList &files, GpgME::Protocol proto);
    void verifyFiles(const QStringList &files, GpgME::Protocol proto);
    void decryptVerifyFiles(const QStringList &files, GpgME::Protocol proto);
    void checksumFiles(const QStringList &files, GpgME::Protocol /* unused */);
    void slotActivateRequested(const QStringList &arguments, const QString &workingDirectory);

    void handleFiles(const QStringList &files, WId parentId = 0);

Q_SIGNALS:
    /* Emitted from slotActivateRequested to enable setting the
     * correct exitValue */
    void setExitValue(int value);

    void configurationChanged();

private Q_SLOTS:
    // used as URL handler for URLs with schemes that shall be blocked
    void blockUrl(const QUrl &url);
    void startGpgAgent();

private:
    class Private;
    const std::unique_ptr<Private> d;
};
