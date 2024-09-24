/* -*- mode: c++; c-basic-offset:4 -*-
    conf/dirservconfigpage.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2004, 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "dirservconfigpage.h"

#include "labelledwidget.h"

#include <settings.h>

#include <Libkleo/Compat>
#include <Libkleo/DirectoryServicesWidget>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyserverConfig>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include "kleopatra_debug.h"
#include <KConfig>
#include <KLocalizedString>
#include <KMessageBox>
#include <QSpinBox>

#include <QCheckBox>
#include <QGroupBox>
#include <QLabel>
#include <QLayout>
#include <QLineEdit>
#include <QTimeEdit>
#include <QVBoxLayout>

#include <gpgme++/engineinfo.h>
#include <gpgme.h>

using namespace Kleo;
using namespace QGpgME;

// Option for configuring X.509 servers (available via gpgconf since GnuPG 2.3.5 and 2.2.34)
static const char s_x509services_componentName[] = "dirmngr";
static const char s_x509services_entryName[] = "ldapserver";

// Legacy option for configuring X.509 servers (deprecated with GnuPG 2.2.28 and 2.3.2)
static const char s_x509services_legacy_componentName[] = "gpgsm";
static const char s_x509services_legacy_entryName[] = "keyserver";

static const char s_pgpservice_componentName[] = "dirmngr";
static const char s_pgpservice_entryName[] = "keyserver";

// legacy config entry used until GnuPG 2.2
static const char s_pgpservice_legacy_componentName[] = "gpg";
static const char s_pgpservice_legacy_entryName[] = "keyserver";

static const char s_timeout_componentName[] = "dirmngr";
static const char s_timeout_entryName[] = "ldaptimeout";

static const char s_maxitems_componentName[] = "dirmngr";
static const char s_maxitems_entryName[] = "max-replies";

class DirectoryServicesConfigurationPage::Private
{
    DirectoryServicesConfigurationPage *q = nullptr;

public:
    Private(DirectoryServicesConfigurationPage *q);

    void load();
    void save();
    void defaults();

private:
    enum EntryMultiplicity {
        SingleValue,
        ListValue,
    };
    enum ShowError {
        DoNotShowError,
        DoShowError,
    };

    void setX509ServerEntry(const std::vector<KeyserverConfig> &servers);
    void load(const Kleo::Settings &settings);

    QGpgME::CryptoConfigEntry *configEntry(const char *componentName,
                                           const char *entryName,
                                           QGpgME::CryptoConfigEntry::ArgType argType,
                                           EntryMultiplicity multiplicity,
                                           ShowError showError);

    Kleo::LabelledWidget<QLineEdit> mOpenPGPKeyserverEdit;
    Kleo::DirectoryServicesWidget *mDirectoryServices = nullptr;
    Kleo::LabelledWidget<QTimeEdit> mTimeout;
    Kleo::LabelledWidget<QSpinBox> mMaxItems;
    QCheckBox *mFetchMissingSignerKeysCB = nullptr;
    QCheckBox *mQueryWKDsForAllUserIDsCB = nullptr;
    QCheckBox *mUseKeyServerCheckBox = nullptr;
    QCheckBox *mRetrieveKeysCheckBox = nullptr;

    QGpgME::CryptoConfigEntry *mOpenPGPServiceEntry = nullptr;
    QGpgME::CryptoConfigEntry *mTimeoutConfigEntry = nullptr;
    QGpgME::CryptoConfigEntry *mMaxItemsConfigEntry = nullptr;
    QGpgME::CryptoConfigEntry *mRetrieveKeysEntry = nullptr;

    QGpgME::CryptoConfig *mConfig = nullptr;
};

DirectoryServicesConfigurationPage::Private::Private(DirectoryServicesConfigurationPage *qq)
    : q{qq}
{
    mConfig = QGpgME::cryptoConfig();
    auto glay = new QGridLayout(q);

    // OpenPGP keyserver
    int row = 0;
    {
        auto groupBox = new QGroupBox{i18nc("@title", "OpenPGP Keyserver")};
        groupBox->setFlat(true);
        auto groupBoxLayout = new QVBoxLayout{groupBox};
        groupBoxLayout->setContentsMargins({});

        groupBoxLayout->addWidget(new QLabel(i18nc("@label:textbox", "Please note that only one OpenPGP keyserver can be configured.")));

        {
            mUseKeyServerCheckBox = new QCheckBox(i18nc("@label:checkbox", "Use OpenPGP keyserver"));
            groupBoxLayout->addWidget(mUseKeyServerCheckBox);
        }
        {
            auto l = new QHBoxLayout{};
            l->setContentsMargins(0, 0, 0, 0);

            groupBoxLayout->addLayout(l);

            mOpenPGPKeyserverEdit.createWidgets(q);
            mOpenPGPKeyserverEdit.label()->setText(i18n("OpenPGP keyserver:"));
            if (engineIsVersion(2, 4, 4) //
                || (engineIsVersion(2, 2, 42) && !engineIsVersion(2, 3, 0))) {
                mOpenPGPKeyserverEdit.widget()->setToolTip( //
                    xi18nc("@info:tooltip",
                           "Enter the address of the keyserver to use when searching for OpenPGP certificates and "
                           "when uploading OpenPGP certificates. If you do not enter an address then an internal "
                           "default will be used. To disable the use of an OpenPGP keyserver enter the special value <emphasis>none</emphasis>."));
            }
            l->addWidget(mOpenPGPKeyserverEdit.label());
            l->addWidget(mOpenPGPKeyserverEdit.widget());
        }

        connect(mUseKeyServerCheckBox, &QCheckBox::toggled, mOpenPGPKeyserverEdit.widget(), &QLineEdit::setEnabled);
        connect(mUseKeyServerCheckBox, &QCheckBox::toggled, q, [this]() {
            if (!mUseKeyServerCheckBox->isChecked()) {
                mOpenPGPKeyserverEdit.widget()->setText(QStringLiteral("none"));
                Q_EMIT q->changed();
            } else if (mOpenPGPKeyserverEdit.widget()->text() == QStringLiteral("none")) {
                mOpenPGPKeyserverEdit.widget()->setText({});
                Q_EMIT q->changed();
            }
        });

        {
            mRetrieveKeysCheckBox = new QCheckBox(i18nc("@label:checkbox", "Search missing keys when verifying a signature"));
            groupBoxLayout->addWidget(mRetrieveKeysCheckBox);
            mRetrieveKeysEntry = configEntry("gpg", "auto-key-retrieve", CryptoConfigEntry::ArgType_None, SingleValue, DoNotShowError);
            mRetrieveKeysCheckBox->setEnabled(!mRetrieveKeysEntry->isReadOnly());
            connect(mRetrieveKeysCheckBox, &QCheckBox::toggled, q, [this]() {
                Q_EMIT q->changed();
            });
        }

        glay->addWidget(groupBox, row, 0, 1, 3);
        connect(mOpenPGPKeyserverEdit.widget(), &QLineEdit::textEdited, q, &DirectoryServicesConfigurationPage::changed);
    }

    // X.509 servers
    if (Settings{}.cmsEnabled()) {
        ++row;
        auto groupBox = new QGroupBox{i18n("X.509 Directory Services"), q};
        groupBox->setFlat(true);
        auto groupBoxLayout = new QVBoxLayout{groupBox};
        groupBoxLayout->setContentsMargins({});

        mDirectoryServices = new Kleo::DirectoryServicesWidget(q);
        if (QLayout *l = mDirectoryServices->layout()) {
            l->setContentsMargins(0, 0, 0, 0);
        }
        groupBoxLayout->addWidget(mDirectoryServices);
        connect(mDirectoryServices, &DirectoryServicesWidget::changed, q, &DirectoryServicesConfigurationPage::changed);

        glay->addWidget(groupBox, row, 0, 1, 3);
    }

    // LDAP timeout
    ++row;
    mTimeout.createWidgets(q);
    mTimeout.label()->setText(i18n("LDAP &timeout (minutes:seconds):"));
    mTimeout.widget()->setDisplayFormat(QStringLiteral("mm:ss"));
    connect(mTimeout.widget(), &QTimeEdit::timeChanged, q, &DirectoryServicesConfigurationPage::changed);
    glay->addWidget(mTimeout.label(), row, 0);
    glay->addWidget(mTimeout.widget(), row, 1);

    // Max number of items returned by queries
    ++row;
    mMaxItems.createWidgets(q);
    mMaxItems.label()->setText(i18n("&Maximum number of items returned by query:"));
    mMaxItems.widget()->setMinimum(0);
    connect(mMaxItems.widget(), &QSpinBox::valueChanged, q, &DirectoryServicesConfigurationPage::changed);
    glay->addWidget(mMaxItems.label(), row, 0);
    glay->addWidget(mMaxItems.widget(), row, 1);

    ++row;
    mFetchMissingSignerKeysCB = new QCheckBox{q};
    mFetchMissingSignerKeysCB->setText(i18nc("@option:check", "Retrieve missing certification keys when importing new keys"));
    mFetchMissingSignerKeysCB->setToolTip(xi18nc("@info:tooltip",
                                                 "If enabled, then Kleopatra will automatically try to retrieve the keys "
                                                 "that were used to certify the user IDs of newly imported OpenPGP keys."));
    connect(mFetchMissingSignerKeysCB, &QCheckBox::toggled, q, &DirectoryServicesConfigurationPage::changed);
    glay->addWidget(mFetchMissingSignerKeysCB, row, 0, 1, 3);

    ++row;
    mQueryWKDsForAllUserIDsCB = new QCheckBox{q};
    mQueryWKDsForAllUserIDsCB->setText(i18nc("@option:check", "Query certificate directories of providers for all user IDs"));
    mQueryWKDsForAllUserIDsCB->setToolTip(xi18nc("@info:tooltip",
                                                 "By default, Kleopatra only queries the certificate directories of providers (WKD) "
                                                 "for user IDs that were originally retrieved from a WKD when you update an OpenPGP "
                                                 "certificate. If this option is enabled, then Kleopatra will query WKDs for all user IDs."));
    connect(mQueryWKDsForAllUserIDsCB, &QCheckBox::toggled, q, &DirectoryServicesConfigurationPage::changed);
    glay->addWidget(mQueryWKDsForAllUserIDsCB, row, 0, 1, 3);

    glay->setRowStretch(++row, 1);
    glay->setColumnStretch(2, 1);
}

static auto readKeyserverConfigs(const CryptoConfigEntry *configEntry)
{
    std::vector<KeyserverConfig> servers;
    if (configEntry) {
        const auto urls = configEntry->urlValueList();
        servers.reserve(urls.size());
        std::transform(std::begin(urls), std::end(urls), std::back_inserter(servers), &KeyserverConfig::fromUrl);
    }
    return servers;
}

void DirectoryServicesConfigurationPage::Private::load(const Kleo::Settings &settings)
{
    if (mDirectoryServices) {
        mDirectoryServices->clear();

        // gpgsm uses the deprecated keyserver option in gpgsm.conf additionally to the ldapserver option in dirmngr.conf;
        // we (try to) read servers from both entries, but always write to the newest existing entry
        const auto *const newEntry =
            configEntry(s_x509services_componentName, s_x509services_entryName, CryptoConfigEntry::ArgType_LDAPURL, ListValue, DoNotShowError);
        const auto *const legacyEntry =
            configEntry(s_x509services_legacy_componentName, s_x509services_legacy_entryName, CryptoConfigEntry::ArgType_LDAPURL, ListValue, DoNotShowError);
        auto entry = newEntry ? newEntry : legacyEntry;
        if (entry) {
            const auto additionalServers = readKeyserverConfigs(legacyEntry);
            auto servers = readKeyserverConfigs(newEntry);
            std::copy(std::begin(additionalServers), std::end(additionalServers), std::back_inserter(servers));
            mDirectoryServices->setKeyservers(servers);
            mDirectoryServices->setReadOnly(entry->isReadOnly());
        } else {
            qCWarning(KLEOPATRA_LOG) << "Unknown or wrong typed config entries" << s_x509services_componentName << "/" << s_x509services_entryName << "and"
                                     << s_x509services_legacy_componentName << "/" << s_x509services_legacy_entryName;

            mDirectoryServices->setDisabled(true);
        }
        mRetrieveKeysCheckBox->setChecked(mRetrieveKeysEntry->boolValue());
    }

    {
        // gpg prefers the deprecated keyserver option in gpg.conf over the keyserver option in dirmngr.conf;
        // therefore, we use the deprecated keyserver option if it is set or if the new option doesn't exist (gpg < 2.1.9)
        auto const newEntry = configEntry(s_pgpservice_componentName, s_pgpservice_entryName, CryptoConfigEntry::ArgType_String, SingleValue, DoNotShowError);
        auto const legacyEntry =
            configEntry(s_pgpservice_legacy_componentName, s_pgpservice_legacy_entryName, CryptoConfigEntry::ArgType_String, SingleValue, DoNotShowError);
        mOpenPGPServiceEntry = ((legacyEntry && legacyEntry->isSet()) || !newEntry) ? legacyEntry : newEntry;

        if (!mOpenPGPServiceEntry) {
            qCWarning(KLEOPATRA_LOG) << "Unknown or wrong typed config entries" << s_pgpservice_componentName << "/" << s_pgpservice_entryName << "and"
                                     << s_pgpservice_legacy_componentName << "/" << s_pgpservice_legacy_entryName;
        } else if (mOpenPGPServiceEntry == legacyEntry) {
            qCDebug(KLEOPATRA_LOG) << "Using config entry" << s_pgpservice_legacy_componentName << "/" << s_pgpservice_legacy_entryName;
        } else {
            qCDebug(KLEOPATRA_LOG) << "Using config entry" << s_pgpservice_componentName << "/" << s_pgpservice_entryName;
        }

        mOpenPGPKeyserverEdit.widget()->setText(mOpenPGPServiceEntry && mOpenPGPServiceEntry->isSet() ? mOpenPGPServiceEntry->stringValue() : QString());
        mUseKeyServerCheckBox->setChecked(mOpenPGPKeyserverEdit.widget()->text() != QStringLiteral("none"));
        mUseKeyServerCheckBox->setEnabled(mOpenPGPServiceEntry && !mOpenPGPServiceEntry->isReadOnly());
        mOpenPGPKeyserverEdit.setEnabled(mOpenPGPServiceEntry && !mOpenPGPServiceEntry->isReadOnly() && mUseKeyServerCheckBox->isChecked());
        if (newEntry && !newEntry->defaultValue().isNull()) {
            mOpenPGPKeyserverEdit.widget()->setPlaceholderText(newEntry->defaultValue().toString());
        } else {
            if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.16") {
                mOpenPGPKeyserverEdit.widget()->setPlaceholderText(QStringLiteral("hkp://keys.gnupg.net"));
            } else {
                mOpenPGPKeyserverEdit.widget()->setPlaceholderText(QStringLiteral("hkps://hkps.pool.sks-keyservers.net"));
            }
        }
    }

    // read LDAP timeout
    // first try to read the config entry as int (GnuPG 2.3)
    mTimeoutConfigEntry = configEntry(s_timeout_componentName, s_timeout_entryName, CryptoConfigEntry::ArgType_Int, SingleValue, DoNotShowError);
    if (!mTimeoutConfigEntry) {
        // if this fails, then try to read the config entry as unsigned int (GnuPG <= 2.2)
        mTimeoutConfigEntry = configEntry(s_timeout_componentName, s_timeout_entryName, CryptoConfigEntry::ArgType_UInt, SingleValue, DoShowError);
    }
    if (mTimeoutConfigEntry) {
        const int ldapTimeout = mTimeoutConfigEntry->argType() == CryptoConfigEntry::ArgType_Int ? mTimeoutConfigEntry->intValue()
                                                                                                 : static_cast<int>(mTimeoutConfigEntry->uintValue());
        const QTime time = QTime(0, 0, 0, 0).addSecs(ldapTimeout);
        // qCDebug(KLEOPATRA_LOG) <<"timeout:" << mTimeoutConfigEntry->uintValue() <<"  ->" << time;
        mTimeout.widget()->setTime(time);
    }
    mTimeout.setEnabled(mTimeoutConfigEntry && !mTimeoutConfigEntry->isReadOnly());

    // read max-replies config entry
    // first try to read the config entry as int (GnuPG 2.3)
    mMaxItemsConfigEntry = configEntry(s_maxitems_componentName, s_maxitems_entryName, CryptoConfigEntry::ArgType_Int, SingleValue, DoNotShowError);
    if (!mMaxItemsConfigEntry) {
        // if this fails, then try to read the config entry as unsigned int (GnuPG <= 2.2)
        mMaxItemsConfigEntry = configEntry(s_maxitems_componentName, s_maxitems_entryName, CryptoConfigEntry::ArgType_UInt, SingleValue, DoShowError);
    }
    if (mMaxItemsConfigEntry) {
        const int value = mMaxItemsConfigEntry->argType() == CryptoConfigEntry::ArgType_Int ? mMaxItemsConfigEntry->intValue()
                                                                                            : static_cast<int>(mMaxItemsConfigEntry->uintValue());
        mMaxItems.widget()->blockSignals(true); // KNumInput emits valueChanged from setValue!
        mMaxItems.widget()->setValue(value);
        mMaxItems.widget()->blockSignals(false);
    }
    mMaxItems.setEnabled(mMaxItemsConfigEntry && !mMaxItemsConfigEntry->isReadOnly());

    mFetchMissingSignerKeysCB->setChecked(settings.retrieveSignerKeysAfterImport());
    mFetchMissingSignerKeysCB->setEnabled(!settings.isImmutable(QStringLiteral("RetrieveSignerKeysAfterImport")));
    mQueryWKDsForAllUserIDsCB->setChecked(settings.queryWKDsForAllUserIDs());
    mQueryWKDsForAllUserIDsCB->setEnabled(!settings.isImmutable(QStringLiteral("QueryWKDsForAllUserIDs")));
}

void DirectoryServicesConfigurationPage::Private::load()
{
    load(Settings{});
}

namespace
{
void updateIntegerConfigEntry(QGpgME::CryptoConfigEntry *configEntry, int value)
{
    if (!configEntry) {
        return;
    }
    if (configEntry->argType() == CryptoConfigEntry::ArgType_Int) {
        if (configEntry->intValue() != value) {
            configEntry->setIntValue(value);
        }
    } else {
        const auto newValue = static_cast<unsigned>(value);
        if (configEntry->uintValue() != newValue) {
            configEntry->setUIntValue(newValue);
        }
    }
}
}

void DirectoryServicesConfigurationPage::Private::setX509ServerEntry(const std::vector<KeyserverConfig> &servers)
{
    const auto newEntry = configEntry(s_x509services_componentName, s_x509services_entryName, CryptoConfigEntry::ArgType_LDAPURL, ListValue, DoNotShowError);
    const auto legacyEntry =
        configEntry(s_x509services_legacy_componentName, s_x509services_legacy_entryName, CryptoConfigEntry::ArgType_LDAPURL, ListValue, DoNotShowError);

    if ((newEntry && newEntry->isReadOnly()) || (legacyEntry && legacyEntry->isReadOnly())) {
        // do not change the config entries if either config entry is read-only
        return;
    }
    QList<QUrl> urls;
    urls.reserve(servers.size());
    std::transform(std::begin(servers), std::end(servers), std::back_inserter(urls), std::mem_fn(&KeyserverConfig::toUrl));
    if (newEntry) {
        // write all servers to the new config entry
        newEntry->setURLValueList(urls);
        // and clear the legacy config entry
        if (legacyEntry) {
            legacyEntry->setURLValueList({});
        }
    } else if (legacyEntry) {
        // write all servers to the legacy config entry if the new entry is not available
        legacyEntry->setURLValueList(urls);
    } else {
        qCWarning(KLEOPATRA_LOG) << "Could not store the X.509 servers. Unknown or wrong typed config entries" << s_x509services_componentName << "/"
                                 << s_x509services_entryName << "and" << s_x509services_legacy_componentName << "/" << s_x509services_legacy_entryName;
    }
}

void DirectoryServicesConfigurationPage::Private::save()
{
    if (mDirectoryServices && mDirectoryServices->isEnabled()) {
        setX509ServerEntry(mDirectoryServices->keyservers());
    }

    if (mOpenPGPServiceEntry) {
        const auto keyserver = mOpenPGPKeyserverEdit.widget()->text().trimmed();
        if (keyserver.isEmpty()) {
            mOpenPGPServiceEntry->resetToDefault();
        } else if (keyserver == QLatin1StringView{"none"}) {
            mOpenPGPServiceEntry->setStringValue(keyserver);
        } else {
            const auto keyserverValue = keyserver.contains(QLatin1Char{':'}) ? keyserver : (QLatin1StringView{"hkps://"} + keyserver);
            mOpenPGPServiceEntry->setStringValue(keyserverValue);
        }
        mRetrieveKeysEntry->setBoolValue(mRetrieveKeysCheckBox->isChecked());
    }

    const QTime time{mTimeout.widget()->time()};
    updateIntegerConfigEntry(mTimeoutConfigEntry, time.minute() * 60 + time.second());

    updateIntegerConfigEntry(mMaxItemsConfigEntry, mMaxItems.widget()->value());

    mConfig->sync(true);

    Settings settings;
    settings.setRetrieveSignerKeysAfterImport(mFetchMissingSignerKeysCB->isChecked());
    settings.setQueryWKDsForAllUserIDs(mQueryWKDsForAllUserIDsCB->isChecked());
    settings.save();
}

void DirectoryServicesConfigurationPage::Private::defaults()
{
    // these guys don't have a default, to clear them:
    if (mDirectoryServices && mDirectoryServices->isEnabled()) {
        setX509ServerEntry({});
    }
    if (mOpenPGPServiceEntry && !mOpenPGPServiceEntry->isReadOnly()) {
        mOpenPGPServiceEntry->setStringValue(QString());
    }
    // these presumably have a default, use that one:
    if (mTimeoutConfigEntry && !mTimeoutConfigEntry->isReadOnly()) {
        mTimeoutConfigEntry->resetToDefault();
    }
    if (mMaxItemsConfigEntry && !mMaxItemsConfigEntry->isReadOnly()) {
        mMaxItemsConfigEntry->resetToDefault();
    }
    if (mRetrieveKeysEntry && !mRetrieveKeysEntry->isReadOnly()) {
        mRetrieveKeysEntry->resetToDefault();
    }

    Settings settings;
    settings.setRetrieveSignerKeysAfterImport(settings.findItem(QStringLiteral("RetrieveSignerKeysAfterImport"))->getDefault().toBool());
    settings.setQueryWKDsForAllUserIDs(settings.findItem(QStringLiteral("QueryWKDsForAllUserIDs"))->getDefault().toBool());

    load(settings);
}

// Find config entry for ldap servers. Implements runtime checks on the configuration option.
CryptoConfigEntry *DirectoryServicesConfigurationPage::Private::configEntry(const char *componentName,
                                                                            const char *entryName,
                                                                            CryptoConfigEntry::ArgType argType,
                                                                            EntryMultiplicity multiplicity,
                                                                            ShowError showError)
{
    CryptoConfigEntry *const entry = Kleo::getCryptoConfigEntry(mConfig, componentName, entryName);
    if (!entry) {
        if (showError == DoShowError) {
            KMessageBox::error(
                q,
                i18n("Backend error: gpgconf does not seem to know the entry for %1/%2", QLatin1StringView(componentName), QLatin1StringView(entryName)));
        }
        return nullptr;
    }
    if (entry->argType() != argType || entry->isList() != bool(multiplicity)) {
        if (showError == DoShowError) {
            KMessageBox::error(q,
                               i18n("Backend error: gpgconf has wrong type for %1/%2: %3 %4",
                                    QLatin1StringView(componentName),
                                    QLatin1StringView(entryName),
                                    entry->argType(),
                                    entry->isList()));
        }
        return nullptr;
    }
    return entry;
}

DirectoryServicesConfigurationPage::DirectoryServicesConfigurationPage(QWidget *parent)
    : KleoConfigModule(parent)
    , d{new Private{this}}
{
}

DirectoryServicesConfigurationPage::~DirectoryServicesConfigurationPage() = default;

void DirectoryServicesConfigurationPage::load()
{
    d->load();
}

void DirectoryServicesConfigurationPage::save()
{
    d->save();
}

void DirectoryServicesConfigurationPage::defaults()
{
    d->defaults();
}

#include "moc_dirservconfigpage.cpp"
