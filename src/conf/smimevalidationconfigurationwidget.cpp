/* -*- mode: c++; c-basic-offset:4 -*-
    conf/smimevalidationconfigurationwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "smimevalidationconfigurationwidget.h"

#include "ui_smimevalidationconfigurationwidget.h"

#include "labelledwidget.h"

#include "smimevalidationpreferences.h"

#include <Libkleo/Compat>

#include <QGpgME/CryptoConfig>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#if HAVE_QDBUS
#include <QDBusConnection>
#endif

using namespace Kleo;
using namespace Kleo::Config;
using namespace QGpgME;

class SMimeValidationConfigurationWidget::Private
{
    friend class ::Kleo::Config::SMimeValidationConfigurationWidget;
    SMimeValidationConfigurationWidget *const q;

public:
    explicit Private(SMimeValidationConfigurationWidget *qq)
        : q(qq)
        , ui(qq)
    {
#if HAVE_QDBUS
        QDBusConnection::sessionBus().connect(QString(), QString(), QStringLiteral("org.kde.kleo.CryptoConfig"), QStringLiteral("changed"), q, SLOT(load()));
#endif
        auto changedSignal = &SMimeValidationConfigurationWidget::changed;
        connect(ui.intervalRefreshCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.intervalRefreshSB, &QSpinBox::valueChanged, q, changedSignal);
        connect(ui.OCSPCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.OCSPResponderURL, &QLineEdit::textChanged, q, changedSignal);

        auto certRequesterSignal = &KleopatraClientCopy::Gui::CertificateRequester::selectedCertificatesChanged;
        connect(ui.OCSPResponderSignature, certRequesterSignal, q, changedSignal);

        connect(ui.doNotCheckCertPolicyCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.neverConsultCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.fetchMissingCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.ignoreServiceURLCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.ignoreHTTPDPCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.disableHTTPCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.honorHTTPProxyRB, &QRadioButton::toggled, q, changedSignal);
        connect(ui.useCustomHTTPProxyRB, &QRadioButton::toggled, q, changedSignal);
        connect(ui.customHTTPProxy, &QLineEdit::textChanged, q, changedSignal);
        connect(ui.ignoreLDAPDPCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.disableLDAPCB, &QCheckBox::toggled, q, changedSignal);
        connect(ui.customLDAPProxy, &QLineEdit::textChanged, q, changedSignal);

        auto enableDisableSlot = [this]() {
            enableDisableActions();
        };
        connect(ui.useCustomHTTPProxyRB, &QRadioButton::toggled, q, enableDisableSlot);
        connect(ui.disableHTTPCB, &QCheckBox::toggled, q, enableDisableSlot);
    }

    bool customHTTPProxyWritable = false;

private:
    void enableDisableActions()
    {
        ui.customHTTPProxy->setEnabled(ui.useCustomHTTPProxyRB->isChecked() && !ui.disableHTTPCB->isChecked() && customHTTPProxyWritable);
    }

private:
    struct UI : Ui_SMimeValidationConfigurationWidget {
        LabelledWidget<KleopatraClientCopy::Gui::CertificateRequester> labelledOCSPResponderSignature;
        LabelledWidget<QLineEdit> labelledOCSPResponderURL;

        explicit UI(SMimeValidationConfigurationWidget *q)
            : Ui_SMimeValidationConfigurationWidget()
        {
            setupUi(q);

            labelledOCSPResponderURL.setWidgets(OCSPResponderURL, OCSPResponderURLLabel);
            labelledOCSPResponderSignature.setWidgets(OCSPResponderSignature, OCSPResponderSignatureLabel);

            OCSPResponderSignature->setOnlyX509CertificatesAllowed(true);
            OCSPResponderSignature->setOnlySigningCertificatesAllowed(true);
            OCSPResponderSignature->setMultipleCertificatesAllowed(false);
            // OCSPResponderSignature->setAllowedKeys( KeySelectionDialog::TrustedKeys|KeySelectionDialog::ValidKeys );
        }
    } ui;
};

SMimeValidationConfigurationWidget::SMimeValidationConfigurationWidget(QWidget *p, Qt::WindowFlags f)
    : QWidget(p, f)
    , d(new Private(this))
{
}

SMimeValidationConfigurationWidget::~SMimeValidationConfigurationWidget()
{
}

static void disableDirmngrWidget(QWidget *w)
{
    w->setEnabled(false);
    w->setWhatsThis(i18n("This option requires dirmngr >= 0.9.0"));
}

static void initializeDirmngrCheckbox(QCheckBox *cb, CryptoConfigEntry *entry)
{
    if (entry) {
        cb->setChecked(entry->boolValue());
    }
    if (!entry || entry->isReadOnly()) {
        disableDirmngrWidget(cb);
    }
}

struct SMIMECryptoConfigEntries {
    enum ShowError {
        DoNotShowError,
        DoShowError,
    };

    SMIMECryptoConfigEntries(CryptoConfig *config)
        : mConfig(config)
        // Checkboxes
        , mCheckUsingOCSPConfigEntry(configEntry("gpgsm", "enable-ocsp", CryptoConfigEntry::ArgType_None))
        , mEnableOCSPsendingConfigEntry(configEntry("dirmngr", "allow-ocsp", CryptoConfigEntry::ArgType_None))
        , mDoNotCheckCertPolicyConfigEntry(configEntry("gpgsm", "disable-policy-checks", CryptoConfigEntry::ArgType_None))
        , mNeverConsultConfigEntry(configEntry("gpgsm", "disable-crl-checks", CryptoConfigEntry::ArgType_None))
        , mFetchMissingConfigEntry(configEntry("gpgsm", "auto-issuer-key-retrieve", CryptoConfigEntry::ArgType_None))
        // dirmngr-0.9.0 options
        , mIgnoreServiceURLEntry(configEntry("dirmngr", "ignore-ocsp-service-url", CryptoConfigEntry::ArgType_None))
        , mIgnoreHTTPDPEntry(configEntry("dirmngr", "ignore-http-dp", CryptoConfigEntry::ArgType_None))
        , mDisableHTTPEntry(configEntry("dirmngr", "disable-http", CryptoConfigEntry::ArgType_None))
        , mHonorHTTPProxy(configEntry("dirmngr", "honor-http-proxy", CryptoConfigEntry::ArgType_None))
        , mIgnoreLDAPDPEntry(configEntry("dirmngr", "ignore-ldap-dp", CryptoConfigEntry::ArgType_None))
        , mDisableLDAPEntry(configEntry("dirmngr", "disable-ldap", CryptoConfigEntry::ArgType_None))
        // Other widgets
        , mOCSPResponderURLConfigEntry(configEntry("dirmngr", "ocsp-responder", CryptoConfigEntry::ArgType_String))
        , mOCSPResponderSignature(configEntry("dirmngr", "ocsp-signer", CryptoConfigEntry::ArgType_String))
        , mCustomHTTPProxy(configEntry("dirmngr", "http-proxy", CryptoConfigEntry::ArgType_String))
        , mCustomLDAPProxy(configEntry("dirmngr", "ldap-proxy", CryptoConfigEntry::ArgType_String))
    {
    }

    CryptoConfigEntry *configEntry(const char *componentName, const char *entryName, int argType, ShowError showError = DoShowError);

    CryptoConfig *const mConfig;

    // Checkboxes
    CryptoConfigEntry *const mCheckUsingOCSPConfigEntry;
    CryptoConfigEntry *const mEnableOCSPsendingConfigEntry;
    CryptoConfigEntry *const mDoNotCheckCertPolicyConfigEntry;
    CryptoConfigEntry *const mNeverConsultConfigEntry;
    CryptoConfigEntry *const mFetchMissingConfigEntry;
    // dirmngr-0.9.0 options
    CryptoConfigEntry *const mIgnoreServiceURLEntry;
    CryptoConfigEntry *const mIgnoreHTTPDPEntry;
    CryptoConfigEntry *const mDisableHTTPEntry;
    CryptoConfigEntry *const mHonorHTTPProxy;
    CryptoConfigEntry *const mIgnoreLDAPDPEntry;
    CryptoConfigEntry *const mDisableLDAPEntry;
    // Other widgets
    CryptoConfigEntry *const mOCSPResponderURLConfigEntry;
    CryptoConfigEntry *const mOCSPResponderSignature;
    CryptoConfigEntry *const mCustomHTTPProxy;
    CryptoConfigEntry *const mCustomLDAPProxy;
};

void SMimeValidationConfigurationWidget::defaults()
{
    qCDebug(KLEOPATRA_LOG) << "not implemented";
}

void SMimeValidationConfigurationWidget::load()
{
    const SMimeValidationPreferences preferences;
    const unsigned int refreshInterval = preferences.refreshInterval();
    d->ui.intervalRefreshCB->setChecked(refreshInterval > 0);
    d->ui.intervalRefreshSB->setValue(refreshInterval);
    const bool isRefreshIntervalImmutable = preferences.isImmutable(QStringLiteral("RefreshInterval"));
    d->ui.intervalRefreshCB->setEnabled(!isRefreshIntervalImmutable);
    d->ui.intervalRefreshSB->setEnabled(!isRefreshIntervalImmutable);

    CryptoConfig *const config = QGpgME::cryptoConfig();
    if (!config) {
        setEnabled(false);
        return;
    }

#if 0
    // crashes other pages' save() by nuking the CryptoConfigEntries under their feet.
    // This was probably not a problem in KMail, where this code comes
    // from. But here, it's fatal.

    // Force re-parsing gpgconf data, in case e.g. kleopatra or "configure backend" was used
    // (which ends up calling us via D-Bus)
    config->clear();
#endif

    // Create config entries
    // Don't keep them around, they'll get deleted by clear(), which could be
    // done by the "configure backend" button even before we save().
    const SMIMECryptoConfigEntries e(config);

    // Initialize GUI items from the config entries

    if (e.mCheckUsingOCSPConfigEntry) {
        d->ui.OCSPCB->setChecked(e.mCheckUsingOCSPConfigEntry->boolValue());
    }
    d->ui.OCSPCB->setEnabled(e.mCheckUsingOCSPConfigEntry && !e.mCheckUsingOCSPConfigEntry->isReadOnly());
    d->ui.OCSPGroupBox->setEnabled(d->ui.OCSPCB->isChecked());

    if (e.mDoNotCheckCertPolicyConfigEntry) {
        d->ui.doNotCheckCertPolicyCB->setChecked(e.mDoNotCheckCertPolicyConfigEntry->boolValue());
    }
    d->ui.doNotCheckCertPolicyCB->setEnabled(e.mDoNotCheckCertPolicyConfigEntry && !e.mDoNotCheckCertPolicyConfigEntry->isReadOnly());
    if (e.mNeverConsultConfigEntry) {
        d->ui.neverConsultCB->setChecked(e.mNeverConsultConfigEntry->boolValue());
    }
    d->ui.neverConsultCB->setEnabled(e.mNeverConsultConfigEntry && !e.mNeverConsultConfigEntry->isReadOnly());
    if (e.mFetchMissingConfigEntry) {
        d->ui.fetchMissingCB->setChecked(e.mFetchMissingConfigEntry->boolValue());
    }
    d->ui.fetchMissingCB->setEnabled(e.mFetchMissingConfigEntry && !e.mFetchMissingConfigEntry->isReadOnly());

    if (e.mOCSPResponderURLConfigEntry) {
        d->ui.OCSPResponderURL->setText(e.mOCSPResponderURLConfigEntry->stringValue());
    }
    d->ui.labelledOCSPResponderURL.setEnabled(e.mOCSPResponderURLConfigEntry && !e.mOCSPResponderURLConfigEntry->isReadOnly());
    if (e.mOCSPResponderSignature) {
        d->ui.OCSPResponderSignature->setSelectedCertificate(e.mOCSPResponderSignature->stringValue());
    }
    d->ui.labelledOCSPResponderSignature.setEnabled(e.mOCSPResponderSignature && !e.mOCSPResponderSignature->isReadOnly());

    // dirmngr-0.9.0 options
    initializeDirmngrCheckbox(d->ui.ignoreServiceURLCB, e.mIgnoreServiceURLEntry);
    initializeDirmngrCheckbox(d->ui.ignoreHTTPDPCB, e.mIgnoreHTTPDPEntry);
    initializeDirmngrCheckbox(d->ui.disableHTTPCB, e.mDisableHTTPEntry);
    initializeDirmngrCheckbox(d->ui.ignoreLDAPDPCB, e.mIgnoreLDAPDPEntry);
    initializeDirmngrCheckbox(d->ui.disableLDAPCB, e.mDisableLDAPEntry);
    if (e.mCustomHTTPProxy) {
        QString systemProxy = QString::fromLocal8Bit(qgetenv("http_proxy"));
        if (systemProxy.isEmpty()) {
            systemProxy = i18n("no proxy");
        }
        d->ui.systemHTTPProxy->setText(i18n("(Current system setting: %1)", systemProxy));
        const bool honor = e.mHonorHTTPProxy && e.mHonorHTTPProxy->boolValue();
        d->ui.honorHTTPProxyRB->setChecked(honor);
        d->ui.useCustomHTTPProxyRB->setChecked(!honor);
        d->ui.customHTTPProxy->setText(e.mCustomHTTPProxy->stringValue());
    }
    d->customHTTPProxyWritable = e.mCustomHTTPProxy && !e.mCustomHTTPProxy->isReadOnly();
    if (!d->customHTTPProxyWritable) {
        disableDirmngrWidget(d->ui.honorHTTPProxyRB);
        disableDirmngrWidget(d->ui.useCustomHTTPProxyRB);
        disableDirmngrWidget(d->ui.systemHTTPProxy);
        disableDirmngrWidget(d->ui.customHTTPProxy);
    }
    if (e.mCustomLDAPProxy) {
        d->ui.customLDAPProxy->setText(e.mCustomLDAPProxy->stringValue());
    }
    if (!e.mCustomLDAPProxy || e.mCustomLDAPProxy->isReadOnly()) {
        disableDirmngrWidget(d->ui.customLDAPProxy);
        disableDirmngrWidget(d->ui.customLDAPLabel);
    }
    d->enableDisableActions();
}

static void saveCheckBoxToKleoEntry(QCheckBox *cb, CryptoConfigEntry *entry)
{
    const bool b = cb->isChecked();
    if (entry && entry->boolValue() != b) {
        entry->setBoolValue(b);
    }
}

void SMimeValidationConfigurationWidget::save() const
{
    CryptoConfig *const config = QGpgME::cryptoConfig();
    if (!config) {
        return;
    }

    {
        SMimeValidationPreferences preferences;
        preferences.setRefreshInterval(d->ui.intervalRefreshCB->isChecked() ? d->ui.intervalRefreshSB->value() : 0);
        preferences.save();
    }

    // Create config entries
    // Don't keep them around, they'll get deleted by clear(), which could be done by the
    // "configure backend" button.
    const SMIMECryptoConfigEntries e(config);

    const bool b = d->ui.OCSPCB->isChecked();
    if (e.mCheckUsingOCSPConfigEntry && e.mCheckUsingOCSPConfigEntry->boolValue() != b) {
        e.mCheckUsingOCSPConfigEntry->setBoolValue(b);
    }
    // Set allow-ocsp together with enable-ocsp
    if (e.mEnableOCSPsendingConfigEntry && e.mEnableOCSPsendingConfigEntry->boolValue() != b) {
        e.mEnableOCSPsendingConfigEntry->setBoolValue(b);
    }

    saveCheckBoxToKleoEntry(d->ui.doNotCheckCertPolicyCB, e.mDoNotCheckCertPolicyConfigEntry);
    saveCheckBoxToKleoEntry(d->ui.neverConsultCB, e.mNeverConsultConfigEntry);
    saveCheckBoxToKleoEntry(d->ui.fetchMissingCB, e.mFetchMissingConfigEntry);

    QString txt = d->ui.OCSPResponderURL->text();
    if (e.mOCSPResponderURLConfigEntry && e.mOCSPResponderURLConfigEntry->stringValue() != txt) {
        e.mOCSPResponderURLConfigEntry->setStringValue(txt);
    }

    txt = d->ui.OCSPResponderSignature->selectedCertificate();
    if (e.mOCSPResponderSignature && e.mOCSPResponderSignature->stringValue() != txt) {
        e.mOCSPResponderSignature->setStringValue(txt);
    }

    // dirmngr-0.9.0 options
    saveCheckBoxToKleoEntry(d->ui.ignoreServiceURLCB, e.mIgnoreServiceURLEntry);
    saveCheckBoxToKleoEntry(d->ui.ignoreHTTPDPCB, e.mIgnoreHTTPDPEntry);
    saveCheckBoxToKleoEntry(d->ui.disableHTTPCB, e.mDisableHTTPEntry);
    saveCheckBoxToKleoEntry(d->ui.ignoreLDAPDPCB, e.mIgnoreLDAPDPEntry);
    saveCheckBoxToKleoEntry(d->ui.disableLDAPCB, e.mDisableLDAPEntry);
    if (e.mCustomHTTPProxy) {
        const bool honor = d->ui.honorHTTPProxyRB->isChecked();
        if (e.mHonorHTTPProxy && e.mHonorHTTPProxy->boolValue() != honor) {
            e.mHonorHTTPProxy->setBoolValue(honor);
        }

        const QString chosenProxy = d->ui.customHTTPProxy->text();
        if (chosenProxy != e.mCustomHTTPProxy->stringValue()) {
            e.mCustomHTTPProxy->setStringValue(chosenProxy);
        }
    }
    txt = d->ui.customLDAPProxy->text();
    if (e.mCustomLDAPProxy && e.mCustomLDAPProxy->stringValue() != txt) {
        e.mCustomLDAPProxy->setStringValue(d->ui.customLDAPProxy->text());
    }

    config->sync(true);
}

CryptoConfigEntry *
SMIMECryptoConfigEntries::configEntry(const char *componentName, const char *entryName, int /*CryptoConfigEntry::ArgType*/ argType, ShowError showError)
{
    CryptoConfigEntry *const entry = getCryptoConfigEntry(mConfig, componentName, entryName);
    if (!entry) {
        if (showError == DoShowError) {
            qCWarning(KLEOPATRA_LOG) << QStringLiteral("Backend error: gpgconf doesn't seem to know the entry for %1/%2")
                                            .arg(QLatin1StringView(componentName), QLatin1StringView(entryName));
        }
        return nullptr;
    }
    if (entry->argType() != argType || entry->isList()) {
        if (showError == DoShowError) {
            qCWarning(KLEOPATRA_LOG) << QStringLiteral("Backend error: gpgconf has wrong type for %1/%2: %3 %4")
                                            .arg(QLatin1StringView(componentName), QLatin1StringView(entryName))
                                            .arg(entry->argType())
                                            .arg(entry->isList());
        }
        return nullptr;
    }
    return entry;
}

#include "moc_smimevalidationconfigurationwidget.cpp"
