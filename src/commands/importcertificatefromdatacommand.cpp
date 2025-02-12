/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "importcertificatefromdatacommand.h"
#include "importcertificatescommand_p.h"

#include <KLocalizedString>

#include <memory>

using namespace GpgME;
using namespace Kleo;
using namespace QGpgME;

class ImportCertificateFromDataCommand::Private : public ImportCertificatesCommand::Private
{
    friend class ::ImportCertificateFromDataCommand;
    ImportCertificateFromDataCommand *q_func() const
    {
        return static_cast<ImportCertificateFromDataCommand *>(q);
    }

public:
    explicit Private(ImportCertificateFromDataCommand *qq, const QByteArray &data, GpgME::Protocol proto, const QString &id);
    ~Private() override;

private:
    QByteArray mData;
    GpgME::Protocol mProto;
    QString mId;
};

ImportCertificateFromDataCommand::Private *ImportCertificateFromDataCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ImportCertificateFromDataCommand::Private *ImportCertificateFromDataCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

ImportCertificateFromDataCommand::Private::Private(ImportCertificateFromDataCommand *qq, const QByteArray &data, GpgME::Protocol proto, const QString &id)
    : ImportCertificatesCommand::Private(qq, nullptr)
    , mData(data)
    , mProto(proto)
    , mId(id)
{
}

ImportCertificateFromDataCommand::Private::~Private()
{
}

#define d d_func()
#define q q_func()

ImportCertificateFromDataCommand::ImportCertificateFromDataCommand(const QByteArray &data, GpgME::Protocol proto, const QString &id)
    : ImportCertificatesCommand(new Private(this, data, proto, id))
{
}

ImportCertificateFromDataCommand::~ImportCertificateFromDataCommand()
{
}

void ImportCertificateFromDataCommand::doStart()
{
    d->setWaitForMoreJobs(true);
    d->startImport(d->mProto, d->mData, d->mId.isEmpty() ? i18n("Notepad") : d->mId);
    d->setWaitForMoreJobs(false);
}

#undef d
#undef q

#include "moc_importcertificatefromdatacommand.cpp"
