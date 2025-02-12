/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "advancedsettingsdialog_p.h"
#include "listwidget.h"

#include "utils/gui-helper.h"

#include <settings.h>

#include <Libkleo/Compat>
#include <Libkleo/Compliance>
#include <Libkleo/GnuPG>

#include <KAdjustingScrollArea>
#include <KLocalizedString>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::NewCertificateUi;
using namespace GpgME;

static const char RSA_KEYSIZES_ENTRY[] = "RSAKeySizes";
static const char RSA_KEYSIZE_LABELS_ENTRY[] = "RSAKeySizeLabels";
static const char CMS_KEY_TYPE_ENTRY[] = "CMSKeyType";

namespace
{

static void set_keysize(QComboBox *cb, unsigned int strength)
{
    if (!cb) {
        return;
    }
    const int idx = cb->findData(static_cast<int>(strength));
    if (idx >= 0) {
        cb->setCurrentIndex(idx);
    }
}

static unsigned int get_keysize(const QComboBox *cb)
{
    if (!cb) {
        return 0;
    }
    const int idx = cb->currentIndex();
    if (idx < 0) {
        return 0;
    }
    return cb->itemData(idx).toInt();
}

static int parseSize(const QString &algoString)
{
    const auto split = algoString.split(QLatin1Char('/'));
    const auto lowered = split[0].toLower().remove(QLatin1Char('-'));

    bool ok;
    auto size = lowered.right(lowered.size() - 3).toInt(&ok);
    if (ok) {
        return size;
    }

    qCWarning(KLEOPATRA_LOG) << "Could not extract size from: " << lowered;
    return 3072;
}

}

struct AdvancedSettingsDialog::UI {
    QTabWidget *tabWidget = nullptr;
    QComboBox *rsaKeyStrengthCB = nullptr;
    QCheckBox *signingCB = nullptr;
    QCheckBox *encryptionCB = nullptr;
    KAdjustingScrollArea *personalTab = nullptr;
    QGroupBox *emailGB = nullptr;
    Kleo::NewCertificateUi::ListWidget *emailLW = nullptr;
    QGroupBox *dnsGB = nullptr;
    Kleo::NewCertificateUi::ListWidget *dnsLW = nullptr;
    QGroupBox *uriGB = nullptr;
    Kleo::NewCertificateUi::ListWidget *uriLW = nullptr;
    QDialogButtonBox *buttonBox = nullptr;

    UI(QDialog *parent)
    {
        parent->setWindowTitle(i18nc("@title:window", "Advanced Settings"));

        auto mainLayout = new QVBoxLayout{parent};

        tabWidget = new QTabWidget{parent};
        tabWidget->setDocumentMode(true);

        {
            auto technicalTab = new KAdjustingScrollArea{tabWidget};

            auto widget = new QWidget;
            technicalTab->setWidget(widget);
            new QVBoxLayout(widget);

            technicalTab->setFocusPolicy(Qt::NoFocus);
            technicalTab->setFrameStyle(QFrame::NoFrame);
            technicalTab->setBackgroundRole(parent->backgroundRole());
            technicalTab->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            technicalTab->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
            auto tabLayout = qobject_cast<QVBoxLayout *>(technicalTab->widget()->layout());

            {
                auto groupBox = new QGroupBox{i18nc("@title:group", "Key Material"), technicalTab};
                auto groupBoxGrid = new QGridLayout{groupBox};

                int row = 0;

                auto label = new QLabel(i18nc("@info:label", "RSA key strength:"));
                groupBoxGrid->addWidget(label, row, 0, 1, 1);
                rsaKeyStrengthCB = new QComboBox{groupBox};
                rsaKeyStrengthCB->setEnabled(true);
                groupBoxGrid->addWidget(rsaKeyStrengthCB, row, 2, 1, 1);

                row++;
                auto subKeyIndentation = new QSpacerItem(13, 13, QSizePolicy::Fixed, QSizePolicy::Minimum);
                groupBoxGrid->addItem(subKeyIndentation, row, 0, 1, 1);

                groupBoxGrid->setColumnStretch(3, 1);

                tabLayout->addWidget(groupBox);
            }
            {
                auto groupBox = new QGroupBox{i18nc("@title:group", "Certificate Usage"), technicalTab};
                auto groupBoxGrid = new QGridLayout{groupBox};

                int row = 0;
                signingCB = new QCheckBox{i18nc("@option:check", "Signing"), groupBox};
                signingCB->setChecked(true);
                groupBoxGrid->addWidget(signingCB, row, 0, 1, 1);

                row++;
                encryptionCB = new QCheckBox{i18nc("@option:check", "Encryption"), groupBox};
                encryptionCB->setChecked(true);
                groupBoxGrid->addWidget(encryptionCB, row, 0, 1, 1);

                row++;
                {
                    auto hbox = new QHBoxLayout;
                    groupBoxGrid->addLayout(hbox, row, 0, 1, 2);
                }

                tabLayout->addWidget(groupBox);
            }

            tabLayout->addStretch(1);

            tabWidget->addTab(technicalTab, i18nc("@title:tab", "Technical Details"));
        }

        {
            personalTab = new KAdjustingScrollArea{tabWidget};

            auto widget = new QWidget;
            personalTab->setWidget(widget);
            new QVBoxLayout(widget);

            personalTab->setFocusPolicy(Qt::NoFocus);
            personalTab->setFrameStyle(QFrame::NoFrame);
            personalTab->setBackgroundRole(parent->backgroundRole());
            personalTab->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            personalTab->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
            auto scrollAreaLayout = qobject_cast<QVBoxLayout *>(personalTab->widget()->layout());

            auto tabGrid = new QGridLayout;

            emailGB = new QGroupBox{i18nc("@title:group", "EMail Addresses"), personalTab};
            {
                auto layout = new QVBoxLayout{emailGB};
                emailLW = new Kleo::NewCertificateUi::ListWidget{emailGB};
                layout->addWidget(emailLW);
            }
            tabGrid->addWidget(emailGB, 2, 0, 2, 1);

            dnsGB = new QGroupBox{i18nc("@title:group", "DNS Names"), personalTab};
            {
                auto layout = new QVBoxLayout{dnsGB};
                dnsLW = new Kleo::NewCertificateUi::ListWidget{dnsGB};
                layout->addWidget(dnsLW);
            }
            tabGrid->addWidget(dnsGB, 2, 1, 1, 1);

            uriGB = new QGroupBox{i18nc("@title:group", "URIs"), personalTab};
            {
                auto layout = new QVBoxLayout{uriGB};
                uriLW = new Kleo::NewCertificateUi::ListWidget{uriGB};
                layout->addWidget(uriLW);
            }
            tabGrid->addWidget(uriGB, 3, 1, 1, 1);

            scrollAreaLayout->addLayout(tabGrid);

            tabWidget->addTab(personalTab, i18nc("@title:tab", "Personal Details"));
        }

        mainLayout->addWidget(tabWidget);

        buttonBox = new QDialogButtonBox{parent};
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);

        mainLayout->addWidget(buttonBox);
    }
};

AdvancedSettingsDialog::AdvancedSettingsDialog(QWidget *parent)
    : QDialog{parent}
    , ui{new UI{this}}
{
    qRegisterMetaType<Subkey::PubkeyAlgo>("Subkey::PubkeyAlgo");

    ui->emailLW->setDefaultValue(i18n("new email"));
    ui->dnsLW->setDefaultValue(i18n("new dns name"));
    ui->uriLW->setDefaultValue(i18n("new uri"));

    fillKeySizeComboBoxen();

    connect(ui->signingCB, &QAbstractButton::toggled, this, &AdvancedSettingsDialog::slotSigningAllowedToggled);
    connect(ui->encryptionCB, &QAbstractButton::toggled, this, &AdvancedSettingsDialog::slotEncryptionAllowedToggled);

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &AdvancedSettingsDialog::accept);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

    loadDefaults();
}

AdvancedSettingsDialog::~AdvancedSettingsDialog() = default;

void AdvancedSettingsDialog::setAdditionalEMailAddresses(const QStringList &items)
{
    ui->emailLW->setItems(items);
}

QStringList AdvancedSettingsDialog::additionalEMailAddresses() const
{
    return ui->emailLW->items();
}

void AdvancedSettingsDialog::setDnsNames(const QStringList &items)
{
    ui->dnsLW->setItems(items);
}

QStringList AdvancedSettingsDialog::dnsNames() const
{
    return ui->dnsLW->items();
}

void AdvancedSettingsDialog::setUris(const QStringList &items)
{
    ui->uriLW->setItems(items);
}

QStringList AdvancedSettingsDialog::uris() const
{
    return ui->uriLW->items();
}

void AdvancedSettingsDialog::setKeyStrength(unsigned int strength)
{
    set_keysize(ui->rsaKeyStrengthCB, strength);
}

unsigned int AdvancedSettingsDialog::keyStrength() const
{
    return get_keysize(ui->rsaKeyStrengthCB);
}

Subkey::PubkeyAlgo AdvancedSettingsDialog::keyType() const
{
    return Subkey::AlgoRSA;
}

void AdvancedSettingsDialog::setSigningAllowed(bool on)
{
    ui->signingCB->setChecked(on);
}

bool AdvancedSettingsDialog::signingAllowed() const
{
    return ui->signingCB->isChecked();
}

void AdvancedSettingsDialog::setEncryptionAllowed(bool on)
{
    ui->encryptionCB->setChecked(on);
}

bool AdvancedSettingsDialog::encryptionAllowed() const
{
    return ui->encryptionCB->isChecked();
}

void AdvancedSettingsDialog::slotSigningAllowedToggled(bool on)
{
    if (!on && !encryptionAllowed()) {
        setEncryptionAllowed(true);
    }
}

void AdvancedSettingsDialog::slotEncryptionAllowedToggled(bool on)
{
    if (!on && !signingAllowed()) {
        setSigningAllowed(true);
    }
}

static void fill_combobox(QComboBox &cb, const QList<int> &sizes, const QStringList &labels)
{
    cb.clear();
    for (int i = 0, end = sizes.size(); i != end; ++i) {
        const int size = std::abs(sizes[i]);
        /* As we respect the defaults configurable in GnuPG, and we also have configurable
         * defaults in Kleopatra its difficult to print out "default" here. To avoid confusion
         * about that its better not to show any default indication.  */
        cb.addItem(i < labels.size() && !labels[i].trimmed().isEmpty()
                       ? i18ncp("%2: some admin-supplied text, %1: key size in bits", "%2 (1 bit)", "%2 (%1 bits)", size, labels[i].trimmed())
                       : i18ncp("%1: key size in bits", "1 bit", "%1 bits", size),
                   size);
        if (sizes[i] < 0) {
            cb.setCurrentIndex(cb.count() - 1);
        }
    }
}

void AdvancedSettingsDialog::fillKeySizeComboBoxen()
{
    const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("CertificateCreationWizard"));

    QList<int> rsaKeySizes = config.readEntry(RSA_KEYSIZES_ENTRY, QList<int>() << 2048 << -3072 << 4096);
    if (DeVSCompliance::isActive()) {
        rsaKeySizes = config.readEntry(RSA_KEYSIZES_ENTRY, QList<int>() << -3072 << 4096);
    }

    const QStringList rsaKeySizeLabels = config.readEntry(RSA_KEYSIZE_LABELS_ENTRY, QStringList());

    fill_combobox(*ui->rsaKeyStrengthCB, rsaKeySizes, rsaKeySizeLabels);
}

// Try to load the default key type from GnuPG
void AdvancedSettingsDialog::loadDefaultGnuPGKeyType()
{
    const auto conf = QGpgME::cryptoConfig();
    if (!conf) {
        qCWarning(KLEOPATRA_LOG) << "Failed to obtain cryptoConfig.";
        return;
    }
    const auto entry = getCryptoConfigEntry(conf, "gpgsm", "default_pubkey_algo");
    if (!entry) {
        qCDebug(KLEOPATRA_LOG) << "GnuPG does not have default key type. Fallback to RSA";
        return;
    }

    qCDebug(KLEOPATRA_LOG) << "Have default key type: " << entry->stringValue();

    // Format is <primarytype>[/usage]+<subkeytype>[/usage]
    const auto split = entry->stringValue().split(QLatin1Char('+'));
    setKeyStrength(parseSize(split[0]));
}

void AdvancedSettingsDialog::loadDefaultKeyType()
{
    const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("CertificateCreationWizard"));

    const QString entry = QLatin1StringView(CMS_KEY_TYPE_ENTRY);
    const QString keyType = config.readEntry(entry).trimmed().toUpper();

    if (keyType.isEmpty() && engineIsVersion(2, 1, 17)) {
        loadDefaultGnuPGKeyType();
    } else {
        if (!keyType.isEmpty() && keyType != QLatin1StringView("RSA"))
            qCWarning(KLEOPATRA_LOG) << "invalid value \"" << qPrintable(keyType) << "\" for entry \"[CertificateCreationWizard]" << qPrintable(entry) << "\"";
    }

    keyTypeImmutable = config.isEntryImmutable(entry);
}

void AdvancedSettingsDialog::loadDefaults()
{
    loadDefaultKeyType();
    updateWidgetVisibility();
}

void AdvancedSettingsDialog::updateWidgetVisibility()
{
    if (keyTypeImmutable) {
        // force usage if key type is forced
        ui->signingCB->setEnabled(false);
        ui->encryptionCB->setEnabled(false);
    } else {
        ui->encryptionCB->setEnabled(true);
    }
}

void AdvancedSettingsDialog::setInitialFocus()
{
    // then try the usage check boxes and the expiration check box
    if (focusFirstEnabledButton({ui->signingCB, ui->encryptionCB})) {
        return;
    }
    // finally, focus the OK button
    ui->buttonBox->button(QDialogButtonBox::Ok)->setFocus();
}

void AdvancedSettingsDialog::accept()
{
    QDialog::accept();
}

void AdvancedSettingsDialog::showEvent(QShowEvent *event)
{
    if (isFirstShowEvent) {
        setInitialFocus();
        isFirstShowEvent = false;
    }
    QDialog::showEvent(event);
}

#include "moc_advancedsettingsdialog_p.cpp"
