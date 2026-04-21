/* -*- mode: c++; c-basic-offset:4 -*-
    crypto/gui/signencryptfileswizard.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <gpgme++/global.h>

#include <QWizard>

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

class ResultPage;
class SigEncPage;

namespace Kleo
{

class SignEncryptFilesWizard : public QWizard
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

    explicit SignEncryptFilesWizard(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~SignEncryptFilesWizard() override;

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
    void clearResults();

    // Outputs
    std::vector<GpgME::Key> resolvedRecipients() const;
    std::vector<GpgME::Key> resolvedSigners() const;
    bool encryptSymmetric() const;

    QString buttonLabel() const;

    void setLabelText(const QString &label);

    // flags the result of the operation as not compliant even if everything looks compliant;
    // this is done when the S/MIME encryption is performed without thorough validation of the
    // certificate chains (i.e. with the "always-trust" option)
    void setForceResultAsNotCompliant(bool notCompliant);
    inline bool forceResultAsNotCompliant() const
    {
        return mForceNotCompliant;
    }

protected:
    void readConfig();
    void writeConfig();

Q_SIGNALS:
    void operationPrepared();

private Q_SLOTS:
    void slotCurrentIdChanged(int);

private:
    SigEncPage *mSigEncPage = nullptr;
    ResultPage *mResultPage = nullptr;
    bool mSigningUserMutable = true;
    bool mEncryptionUserMutable = true;
    bool mForceNotCompliant = false;
};

}
