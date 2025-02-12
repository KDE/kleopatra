/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "utils/metatypes_for_gpgmepp_key.h"

#include <QDialog>

#include <gpgme++/key.h>

#include <memory>

class AdvancedSettingsDialog : public QDialog
{
    Q_OBJECT
    Q_PROPERTY(QStringList additionalEMailAddresses READ additionalEMailAddresses WRITE setAdditionalEMailAddresses)
    Q_PROPERTY(QStringList dnsNames READ dnsNames WRITE setDnsNames)
    Q_PROPERTY(QStringList uris READ uris WRITE setUris)
    Q_PROPERTY(uint keyStrength READ keyStrength WRITE setKeyStrength)
    Q_PROPERTY(GpgME::Subkey::PubkeyAlgo keyType READ keyType)
    Q_PROPERTY(bool signingAllowed READ signingAllowed WRITE setSigningAllowed)
    Q_PROPERTY(bool encryptionAllowed READ encryptionAllowed WRITE setEncryptionAllowed)
public:
    explicit AdvancedSettingsDialog(QWidget *parent = nullptr);
    ~AdvancedSettingsDialog() override;

    void setAdditionalEMailAddresses(const QStringList &items);
    QStringList additionalEMailAddresses() const;

    void setDnsNames(const QStringList &items);
    QStringList dnsNames() const;

    void setUris(const QStringList &items);
    QStringList uris() const;

    void setKeyStrength(unsigned int strength);
    unsigned int keyStrength() const;

    GpgME::Subkey::PubkeyAlgo keyType() const;

    void setSigningAllowed(bool on);
    bool signingAllowed() const;

    void setEncryptionAllowed(bool on);
    bool encryptionAllowed() const;

Q_SIGNALS:
    void changed();

private Q_SLOTS:
    void slotSigningAllowedToggled(bool on);
    void slotEncryptionAllowedToggled(bool on);

private:
    void fillKeySizeComboBoxen();
    void loadDefaultKeyType();
    void loadDefaultGnuPGKeyType();
    void loadDefaults();
    void updateWidgetVisibility();
    void setInitialFocus();

protected:
    void accept() override;
    void showEvent(QShowEvent *event) override;

private:
    struct UI;
    std::unique_ptr<UI> ui;

    unsigned int cmsDefaultAlgorithm = GpgME::Subkey::AlgoRSA;
    bool keyTypeImmutable = false;
    bool isFirstShowEvent = true;
};
