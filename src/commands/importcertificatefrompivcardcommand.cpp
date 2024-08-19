/*  commands/importcertificatefrompivcardcommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "importcertificatefrompivcardcommand.h"

#include "cardcommand_p.h"

#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"

#include "commands/importcertificatefromdatacommand.h"

#include <KLocalizedString>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;

class ImportCertificateFromPIVCardCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::ImportCertificateFromPIVCardCommand;
    ImportCertificateFromPIVCardCommand *q_func() const
    {
        return static_cast<ImportCertificateFromPIVCardCommand *>(q);
    }

public:
    explicit Private(ImportCertificateFromPIVCardCommand *qq, const std::string &slot, const std::string &serialno, QWidget *parent);
    ~Private() override;

private:
    void start();
    void importFinished();
    void importCanceled();

private:
    std::string cardSlot;
    bool hasBeenCanceled = false;
};

ImportCertificateFromPIVCardCommand::Private *ImportCertificateFromPIVCardCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ImportCertificateFromPIVCardCommand::Private *ImportCertificateFromPIVCardCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define q q_func()
#define d d_func()

ImportCertificateFromPIVCardCommand::Private::Private(ImportCertificateFromPIVCardCommand *qq,
                                                      const std::string &slot,
                                                      const std::string &serialno,
                                                      QWidget *parent)
    : CardCommand::Private(qq, serialno, parent)
    , cardSlot(slot)
{
}

ImportCertificateFromPIVCardCommand::Private::~Private()
{
}

void ImportCertificateFromPIVCardCommand::Private::start()
{
    qCDebug(KLEOPATRA_LOG) << "ImportCertificateFromPIVCardCommand::Private::start()";

    const auto pivCard = ReaderStatus::instance()->getCard<PIVCard>(serialNumber());
    if (!pivCard) {
        error(i18n("Failed to find the PIV card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    const std::string certificateData = pivCard->certificateData(cardSlot);
    if (certificateData.empty()) {
        error(i18n("Sorry! No certificate to import from this card slot was found."));
        finished();
        return;
    }

    auto cmd = new ImportCertificateFromDataCommand(QByteArray::fromStdString(certificateData), GpgME::CMS, i18n("Card Certificate"));
    connect(cmd, &ImportCertificateFromDataCommand::finished, q, [this]() {
        importFinished();
    });
    connect(cmd, &ImportCertificateFromDataCommand::canceled, q, [this]() {
        importCanceled();
    });
    cmd->start();
}

void ImportCertificateFromPIVCardCommand::Private::importFinished()
{
    qCDebug(KLEOPATRA_LOG) << "ImportCertificateFromPIVCardCommand::importFinished()";
    if (!hasBeenCanceled) {
        finished();
    }
}

void ImportCertificateFromPIVCardCommand::Private::importCanceled()
{
    qCDebug(KLEOPATRA_LOG) << "ImportCertificateFromPIVCardCommand::importCanceled()";
    hasBeenCanceled = true;
    canceled();
}

ImportCertificateFromPIVCardCommand::ImportCertificateFromPIVCardCommand(const std::string &cardSlot, const std::string &serialno, QWidget *parent)
    : CardCommand(new Private(this, cardSlot, serialno, parent))
{
}

ImportCertificateFromPIVCardCommand::~ImportCertificateFromPIVCardCommand()
{
    qCDebug(KLEOPATRA_LOG) << "ImportCertificateFromPIVCardCommand::~ImportCertificateFromPIVCardCommand()";
}

void ImportCertificateFromPIVCardCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG) << "ImportCertificateFromPIVCardCommand::doStart()";

    d->start();
}

void ImportCertificateFromPIVCardCommand::doCancel()
{
}

#undef q_func
#undef d_func

#include "moc_importcertificatefrompivcardcommand.cpp"
