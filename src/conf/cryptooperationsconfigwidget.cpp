/*
    cryptooperationsconfigwidget.cpp

    This file is part of kleopatra, the KDE key manager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config-kleopatra.h>

#include "cryptooperationsconfigwidget.h"
#include "kleopatra_debug.h"

#include <settings.h>

#include <Libkleo/ChecksumDefinition>
#include <Libkleo/KeyFilterManager>
#include <libkleo/classifyconfig.h>

#include <KConfig>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

#include <memory>

using namespace Kleo;
using namespace Kleo::Config;

CryptoOperationsConfigWidget::CryptoOperationsConfigWidget(QWidget *p, Qt::WindowFlags f)
    : QWidget{p, f}
{
    setupGui();
}

void CryptoOperationsConfigWidget::setupGui()
{
    auto baseLay = new QVBoxLayout(this);

    mPGPFileExtCB = new QCheckBox(i18n(R"(Create OpenPGP encrypted files with ".pgp" file extensions instead of ".gpg")"));
    mASCIIArmorCB = new QCheckBox(i18n("Create signed or encrypted files as text files."));
    mASCIIArmorCB->setToolTip(i18nc("@info",
                                    "Set this option to encode encrypted or signed files as base64 encoded text. "
                                    "So that they can be opened with an editor or sent in a mail body. "
                                    "This will increase file size by one third."));
    mTreatP7mEmailCB = new QCheckBox(i18nc("@option:check", "Treat .p7m files without extensions as mails."));
    mAutoDecryptVerifyCB = new QCheckBox(i18n("Automatically start operation based on input detection for decrypt/verify."));
    mAutoExtractArchivesCB = new QCheckBox(i18n("Automatically extract file archives after decryption"));
    mTmpDirCB = new QCheckBox(i18n("Create temporary decrypted files in the folder of the encrypted file."));
    mTmpDirCB->setToolTip(i18nc("@info", "Set this option to avoid using the users temporary directory."));
    mSymmetricOnlyCB = new QCheckBox(i18n("Use symmetric encryption only."));
    mSymmetricOnlyCB->setToolTip(i18nc("@info", "Set this option to disable public key encryption."));

    baseLay->addWidget(mPGPFileExtCB);
    baseLay->addWidget(mTreatP7mEmailCB);
    baseLay->addWidget(mAutoDecryptVerifyCB);
    baseLay->addWidget(mAutoExtractArchivesCB);
    baseLay->addWidget(mASCIIArmorCB);
    baseLay->addWidget(mTmpDirCB);
    baseLay->addWidget(mSymmetricOnlyCB);

    auto comboLay = new QGridLayout;

    mChecksumDefinitionCB.createWidgets(this);
    mChecksumDefinitionCB.label()->setText(i18n("Checksum program to use when creating checksum files:"));
    comboLay->addWidget(mChecksumDefinitionCB.label(), 0, 0);
    comboLay->addWidget(mChecksumDefinitionCB.widget(), 0, 1);

    mArchiveDefinitionCB.createWidgets(this);
    mArchiveDefinitionCB.label()->setText(i18n("Archive command to use when archiving files:"));
    comboLay->addWidget(mArchiveDefinitionCB.label(), 1, 0);
    comboLay->addWidget(mArchiveDefinitionCB.widget(), 1, 1);

    baseLay->addLayout(comboLay);
    baseLay->addStretch(1);

    for (auto cb : findChildren<QCheckBox *>()) {
        connect(cb, &QCheckBox::toggled, this, &CryptoOperationsConfigWidget::changed);
    }
    for (auto combo : findChildren<QComboBox *>()) {
        connect(combo, qOverload<int>(&QComboBox::currentIndexChanged), this, &CryptoOperationsConfigWidget::changed);
    }
}

CryptoOperationsConfigWidget::~CryptoOperationsConfigWidget()
{
}

void CryptoOperationsConfigWidget::defaults()
{
    Settings settings;
    settings.setUsePGPFileExt(settings.findItem(QStringLiteral("UsePGPFileExt"))->getDefault().toBool());
    settings.setAutoDecryptVerify(settings.findItem(QStringLiteral("AutoDecryptVerify"))->getDefault().toBool());
    settings.setAutoExtractArchives(settings.findItem(QStringLiteral("AutoExtractArchives"))->getDefault().toBool());
    settings.setAddASCIIArmor(settings.findItem(QStringLiteral("AddASCIIArmor"))->getDefault().toBool());
    settings.setDontUseTmpDir(settings.findItem(QStringLiteral("DontUseTmpDir"))->getDefault().toBool());
    settings.setSymmetricEncryptionOnly(settings.findItem(QStringLiteral("SymmetricEncryptionOnly"))->getDefault().toBool());
    settings.setArchiveCommand(settings.findItem(QStringLiteral("ArchiveCommand"))->getDefault().toString());

    ClassifyConfig classifyConfig;
    classifyConfig.setP7mWithoutExtensionAreEmail(classifyConfig.defaultP7mWithoutExtensionAreEmailValue());

    load(settings, classifyConfig);
}

void CryptoOperationsConfigWidget::load(const Kleo::Settings &settings, const Kleo::ClassifyConfig &classifyConfig)
{
    mPGPFileExtCB->setChecked(settings.usePGPFileExt());
    mPGPFileExtCB->setEnabled(!settings.isImmutable(QStringLiteral("UsePGPFileExt")));
    mAutoDecryptVerifyCB->setChecked(settings.autoDecryptVerify());
    mAutoDecryptVerifyCB->setEnabled(!settings.isImmutable(QStringLiteral("AutoDecryptVerify")));
    mAutoExtractArchivesCB->setChecked(settings.autoExtractArchives());
    mAutoExtractArchivesCB->setEnabled(!settings.isImmutable(QStringLiteral("AutoExtractArchives")));
    mASCIIArmorCB->setChecked(settings.addASCIIArmor());
    mASCIIArmorCB->setEnabled(!settings.isImmutable(QStringLiteral("AddASCIIArmor")));
    mTmpDirCB->setChecked(settings.dontUseTmpDir());
    mTmpDirCB->setEnabled(!settings.isImmutable(QStringLiteral("DontUseTmpDir")));
    mSymmetricOnlyCB->setChecked(settings.symmetricEncryptionOnly());
    mSymmetricOnlyCB->setEnabled(!settings.isImmutable(QStringLiteral("SymmetricEncryptionOnly")));
    mTreatP7mEmailCB->setChecked(classifyConfig.p7mWithoutExtensionAreEmail());
    mTreatP7mEmailCB->setEnabled(!classifyConfig.isP7mWithoutExtensionAreEmailImmutable());

    const auto defaultChecksumDefinitionId = settings.checksumDefinitionId();
    {
        const auto index = mChecksumDefinitionCB.widget()->findData(defaultChecksumDefinitionId);
        if (index >= 0) {
            mChecksumDefinitionCB.widget()->setCurrentIndex(index);
        } else {
            qCWarning(KLEOPATRA_LOG) << "No checksum definition found with id" << defaultChecksumDefinitionId;
        }
    }
    mChecksumDefinitionCB.setEnabled(!settings.isImmutable(QStringLiteral("ChecksumDefinitionId")));

    const auto ad_default_id = settings.archiveCommand();
    {
        const auto index = mArchiveDefinitionCB.widget()->findData(ad_default_id);
        if (index >= 0) {
            mArchiveDefinitionCB.widget()->setCurrentIndex(index);
        } else {
            qCWarning(KLEOPATRA_LOG) << "No archive definition found with id" << ad_default_id;
        }
    }
    mArchiveDefinitionCB.setEnabled(!settings.isImmutable(QStringLiteral("ArchiveCommand")));
}

void CryptoOperationsConfigWidget::load()
{
    mChecksumDefinitionCB.widget()->clear();
    const auto cds = ChecksumDefinition::getChecksumDefinitions();
    for (const std::shared_ptr<ChecksumDefinition> &cd : cds) {
        mChecksumDefinitionCB.widget()->addItem(cd->label(), QVariant{cd->id()});
    }

    // This is a weird hack but because we are a KCM we can't link
    // against ArchiveDefinition which pulls in loads of other classes.
    // So we do the parsing which archive definitions exist here ourself.
    mArchiveDefinitionCB.widget()->clear();
    if (KSharedConfigPtr config = KSharedConfig::openConfig(QStringLiteral("libkleopatrarc"))) {
        const QStringList groups = config->groupList().filter(QRegularExpression(QStringLiteral("^Archive Definition #")));
        for (const QString &group : groups) {
            const KConfigGroup cGroup(config, group);
            const QString id = cGroup.readEntryUntranslated(QStringLiteral("id"));
            const QString name = cGroup.readEntry("Name");
            mArchiveDefinitionCB.widget()->addItem(name, QVariant(id));
        }
    }

    load(Settings{}, ClassifyConfig{});
}

void CryptoOperationsConfigWidget::save()
{
    Settings settings;
    settings.setUsePGPFileExt(mPGPFileExtCB->isChecked());
    settings.setAutoDecryptVerify(mAutoDecryptVerifyCB->isChecked());
    settings.setAutoExtractArchives(mAutoExtractArchivesCB->isChecked());
    settings.setAddASCIIArmor(mASCIIArmorCB->isChecked());
    settings.setDontUseTmpDir(mTmpDirCB->isChecked());
    settings.setSymmetricEncryptionOnly(mSymmetricOnlyCB->isChecked());

    const int idx = mChecksumDefinitionCB.widget()->currentIndex();
    if (idx >= 0) {
        const auto id = mChecksumDefinitionCB.widget()->itemData(idx).toString();
        settings.setChecksumDefinitionId(id);
    }

    const int aidx = mArchiveDefinitionCB.widget()->currentIndex();
    if (aidx >= 0) {
        const QString id = mArchiveDefinitionCB.widget()->itemData(aidx).toString();
        settings.setArchiveCommand(id);
    }

    settings.save();

    ClassifyConfig classifyConfig;
    classifyConfig.setP7mWithoutExtensionAreEmail(mTreatP7mEmailCB->isChecked());
    classifyConfig.save();
}
