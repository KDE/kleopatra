/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <Libkleo/ApplicationPaletteWatcher>

#include <gpgme++/global.h>

#include <QDialog>
#include <QMap>

#include <memory>

namespace GpgME
{
class Key;
}

namespace Kleo
{
namespace Crypto
{
class TaskCollection;
}
}

class SignEncryptResultPage;
class SigEncPage;

namespace Kleo
{

class SignEncryptFilesDialog : public QDialog
{
    Q_OBJECT
public:
    enum KindNames {
        SignatureCMS,
        SignaturePGP,
        CombinedPGP,
        EncryptedPGP,
        EncryptedCMS,
        Directory,
    };

    explicit SignEncryptFilesDialog(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~SignEncryptFilesDialog() override;

    // Inputs
    void setSigningPreset(bool preset);
    void setSigningUserMutable(bool mut);

    void setEncryptionPreset(bool preset);
    void setEncryptionUserMutable(bool mut);

    void setArchiveForced(bool archive);
    void setArchiveMutable(bool archive);

    void setSingleFile(bool singleFile);

    void setOutputNames(const QMap<int, QString> &nameMap) const;
    QMap<int, QString> outputNames() const;

    void setTaskCollection(const std::shared_ptr<Kleo::Crypto::TaskCollection> &coll);

    // Outputs
    std::vector<GpgME::Key> resolvedRecipients() const;
    std::vector<GpgME::Key> resolvedSigners() const;
    bool encryptSymmetric() const;

protected:
    void readConfig();
    void writeConfig();

Q_SIGNALS:
    void operationPrepared();

private:
    void updateButtons();

    ApplicationPaletteWatcher mAppPaletteWatcher;
    SigEncPage *mSigEncPage = nullptr;
    SignEncryptResultPage *mResultPage = nullptr;
    QPushButton *mOkButton = nullptr;
    QPushButton *mComplianceLabelButton = nullptr;
    bool mSigningUserMutable = true;
    bool mEncryptionUserMutable = true;
};

}
