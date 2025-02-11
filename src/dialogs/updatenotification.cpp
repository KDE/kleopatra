/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "updatenotification.h"

#include <view/htmllabel.h>

#include <Libkleo/Compat>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>

#include "kleopatra_debug.h"

#include <QCheckBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QIcon>
#include <QLabel>
#include <QProcess>
#include <QProgressDialog>
#include <QPushButton>
#include <QRegularExpression>
#include <QUrl>

#include <KAboutData>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <gpgme++/error.h>
#include <gpgme++/gpgmefw.h>
#include <gpgme++/swdbresult.h>

using namespace Kleo;

using namespace Qt::Literals::StringLiterals;

namespace
{
static void gpgconf_set_update_check(bool value)
{
    auto conf = QGpgME::cryptoConfig();
    auto entry = getCryptoConfigEntry(conf, "dirmngr", "allow-version-check");
    if (!entry) {
        qCDebug(KLEOPATRA_LOG) << "allow-version-check entry not found";
        return;
    }
    if (entry->boolValue() != value) {
        entry->setBoolValue(value);
        conf->sync(true);
    }
}
} // namespace

void UpdateNotification::forceUpdateCheck(QWidget *parent)
{
    auto proc = new QProcess;

    proc->setProgram(gnupgInstallPath() + QStringLiteral("/gpg-connect-agent.exe"));
    proc->setArguments({
        QStringLiteral("--dirmngr"),
        QStringLiteral("loadswdb --force"),
        QStringLiteral("/bye"),
    });

    auto progress = new QProgressDialog(i18n("Searching for updates..."), i18n("Cancel"), 0, 0, parent);
    progress->setMinimumDuration(0);
    progress->show();

    connect(progress, &QProgressDialog::canceled, proc, [proc]() {
        proc->kill();
        qCDebug(KLEOPATRA_LOG) << "Update force canceled. Output:" << QString::fromLocal8Bit(proc->readAllStandardOutput())
                               << "stderr:" << QString::fromLocal8Bit(proc->readAllStandardError());
    });

    connect(proc, &QProcess::finished, progress, [parent, progress, proc](int exitCode, QProcess::ExitStatus exitStatus) {
        qCDebug(KLEOPATRA_LOG) << "Update force exited with status:" << exitStatus << "code:" << exitCode;
        delete progress;
        proc->deleteLater();
        UpdateNotification::checkUpdate(parent, exitStatus == QProcess::NormalExit);
    });

    qCDebug(KLEOPATRA_LOG) << "Starting:" << proc->program() << "args" << proc->arguments();

    proc->start();
}
#ifdef Q_OS_WIN
/* Extract the actual version number (conforming to the semanticversioning spec)
 * from the Version strings which might be used for Gpg4win / GnuPG VS-Desktop
 * which are optionally prefixed with some text followed by a dash
 * e.g. "Gpg4win-3.1.15-beta15"; see https://dev.gnupg.org/T5663 */
static const QByteArray extractVersionNumber(const QString &versionString)
{
    static const QRegularExpression catchSemVerRegExp{QLatin1StringView{R"(-([0-9]+(?:\.[0-9]+)*(?:-[.0-9A-Za-z-]+)?(?:\+[.0-9a-zA-Z-]+)?)\)?$)"}};

    const auto match = catchSemVerRegExp.match(versionString);
    const auto current = match.hasMatch() ? match.captured(1) : versionString;
    return current.toUtf8();
}
#endif

void UpdateNotification::checkUpdate(QWidget *parent, bool force)
{
#ifdef Q_OS_WIN
    KConfigGroup updatecfg(KSharedConfig::openConfig(), QStringLiteral("UpdateNotification"));

    if (updatecfg.readEntry("NeverShow", false) && !force) {
        return;
    }

    // Gpg defaults to no update check. For Gpg4win we want this
    // enabled if the user does not explicitly disable update
    // checks neverShow would be true in that case or
    // we would have set AllowVersionCheck once and the user
    // explicitly removed that.
    if (force || updatecfg.readEntry("AllowVersionCheckSetOnce", false)) {
        gpgconf_set_update_check(true);
        updatecfg.writeEntry("AllowVersionCheckSetOnce", true);
    }

    GpgME::Error err;
    const auto lastshown = updatecfg.readEntry("LastShown", QDateTime());

    if (!force && lastshown.isValid() && lastshown.addSecs(20 * 60 * 60) > QDateTime::currentDateTime()) {
        qDebug() << QDateTime::currentDateTime().addSecs(20 * 60 * 60);
        return;
    }

    const auto current = extractVersionNumber(KAboutData::applicationData().version());

    const auto results = GpgME::SwdbResult::query("gpg4win", current.constData(), &err);
    if (err) {
        qCDebug(KLEOPATRA_LOG) << "update check failed: " << Formatting::errorAsString(err);
        return;
    }

    if (results.size() != 1) {
        /* Should not happen */
        qCDebug(KLEOPATRA_LOG) << "more then one result";
        return;
    }

    const auto result = results[0];

    if (result.update()) {
        const QString newVersion = QStringLiteral("%1.%2.%3").arg(result.version().major).arg(result.version().minor).arg(result.version().patch);
        qCDebug(KLEOPATRA_LOG) << "Have update to version:" << newVersion;
        UpdateNotification notifier(parent, newVersion);
        notifier.exec();
        updatecfg.writeEntry("LastShown", QDateTime::currentDateTime());
        updatecfg.sync();
    } else {
        qCDebug(KLEOPATRA_LOG) << "No update for:" << current;
        if (force) {
            KMessageBox::information(parent, i18nc("@info", "No update found in the available version database."), i18nc("@title", "Up to date"));
        }
    }
#else
    Q_UNUSED(parent)
    Q_UNUSED(force)
#endif
}

UpdateNotification::UpdateNotification(QWidget *parent, const QString &version)
    : QDialog(parent)
{
    resize(400, 200);
    auto lay = new QGridLayout(this);
    auto logo = new QLabel;
    logo->setMaximumWidth(110);

    setAttribute(Qt::WA_QuitOnClose, false);

    logo->setPixmap(QPixmap{u":/gpg4win/gpg4win.png"_s}.scaled(100, 100, Qt::KeepAspectRatio, Qt::SmoothTransformation));

    auto label = new HtmlLabel;
    const QString boldVersion = QStringLiteral("<b>%1</b>").arg(version);
    label->setHtml(i18nc("%1 is the version number", "Version %1 is available.", boldVersion) + QStringLiteral("<br><br>")
                   + i18nc("Link to NEWS style changelog", "See the <a href=\"https://www.gpg4win.org/change-history.html\">new features</a>."));
    label->setOpenExternalLinks(true);
    label->setTextInteractionFlags(Qt::TextBrowserInteraction);
    label->setWordWrap(true);
    setWindowTitle(i18nc("@title:window", "Update Available"));
    setWindowIcon(QIcon(QLatin1StringView("gpg4win")));

    lay->addWidget(logo, 0, 0);
    lay->addWidget(label, 0, 1);
    const auto chk = new QCheckBox(i18nc("@option:check", "Show this notification for future updates."));
    lay->addWidget(chk, 1, 0, 1, -1);

    KConfigGroup updatecfg(KSharedConfig::openConfig(), QStringLiteral("UpdateNotification"));
    chk->setChecked(!updatecfg.readEntry("NeverShow", false));

    const auto bb = new QDialogButtonBox();
    const auto b = bb->addButton(i18nc("@action:button", "&Get update"), QDialogButtonBox::AcceptRole);
    b->setDefault(true);
    b->setIcon(QIcon::fromTheme(QStringLiteral("arrow-down")));
    bb->addButton(QDialogButtonBox::Cancel);
    lay->addWidget(bb, 2, 0, 1, -1);
    connect(bb, &QDialogButtonBox::accepted, this, [this, chk]() {
        QDesktopServices::openUrl(QUrl(QStringLiteral("https://www.gpg4win.org/download.html")));
        KConfigGroup updatecfg(KSharedConfig::openConfig(), QStringLiteral("UpdateNotification"));
        updatecfg.writeEntry("NeverShow", !chk->isChecked());
        gpgconf_set_update_check(chk->isChecked());
        QDialog::accept();
    });
    connect(bb, &QDialogButtonBox::rejected, this, [this, chk]() {
        KConfigGroup updatecfg(KSharedConfig::openConfig(), QStringLiteral("UpdateNotification"));
        updatecfg.writeEntry("NeverShow", !chk->isChecked());
        gpgconf_set_update_check(chk->isChecked());
        QDialog::reject();
    });
}
