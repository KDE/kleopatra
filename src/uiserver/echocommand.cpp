/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "echocommand.h"

#include <utils/input.h>
#include <utils/output.h>

#include <Libkleo/KleoException>

#include <gpg-error.h>

#include <KLocalizedString>

#include <QByteArray>
#include <QIODevice>
#include <QVariant>

#include <algorithm>
#include <string>

using namespace Kleo;

static const char option_prefix[] = "prefix";

class EchoCommand::Private
{
public:
    int operationsInFlight = 0;
    QByteArray buffer;
};

EchoCommand::EchoCommand()
    : QObject()
    , AssuanCommandMixin<EchoCommand>()
    , d(new Private)
{
}

EchoCommand::~EchoCommand()
{
}

int EchoCommand::doStart()
{
    const std::vector<std::shared_ptr<Input>> in = inputs(), msg = messages();
    const std::vector<std::shared_ptr<Output>> out = outputs();

    if (!in.empty() && out.empty()) {
        return makeError(GPG_ERR_NOT_SUPPORTED);
    }

    if (!msg.empty()) {
        return makeError(GPG_ERR_NOT_SUPPORTED);
    }

    if (hasOption(option_prefix) && !option(option_prefix).toByteArray().isEmpty()) {
        return makeError(GPG_ERR_NOT_IMPLEMENTED);
    }

    std::string keyword;
    if (hasOption("inquire")) {
        keyword = option("inquire").toString().toStdString();
        if (keyword.empty()) {
            return makeError(GPG_ERR_INV_ARG);
        }
    }

    const std::string output = option("text").toString().toStdString();

    // aaand ACTION:

    // 1. echo the command line though the status channel
    sendStatus("ECHO", output.empty() ? QString() : QLatin1StringView(output.c_str()));

    // 2. if --inquire was given, inquire more data from the client:
    if (!keyword.empty()) {
        if (const int err = inquire(keyword.c_str(), this, SLOT(slotInquireData(int, QByteArray)))) {
            return err;
        } else {
            ++d->operationsInFlight;
        }
    }

    // 3. if INPUT was given, start the data pump for input->output
    if (const std::shared_ptr<QIODevice> i = in.at(0)->ioDevice()) {
        const std::shared_ptr<QIODevice> o = out.at(0)->ioDevice();

        ++d->operationsInFlight;

        connect(i.get(), &QIODevice::readyRead, this, &EchoCommand::slotInputReadyRead);
        connect(o.get(), &QIODevice::bytesWritten, this, &EchoCommand::slotOutputBytesWritten);

        if (i->bytesAvailable()) {
            slotInputReadyRead();
        }
    }

    if (!d->operationsInFlight) {
        done();
    }
    return 0;
}

void EchoCommand::doCanceled()
{
}

void EchoCommand::slotInquireData(int rc, const QByteArray &data)
{
    --d->operationsInFlight;

    if (rc) {
        done(rc);
        return;
    }

    try {
        sendStatus("ECHOINQ", QLatin1StringView(data));
        if (!d->operationsInFlight) {
            done();
        }
    } catch (const Exception &e) {
        done(e.error(), e.message());
    } catch (const std::exception &e) {
        done(makeError(GPG_ERR_UNEXPECTED),
             i18n("Caught unexpected exception in SignCommand::Private::slotMicAlgDetermined: %1", QString::fromLocal8Bit(e.what())));
    } catch (...) {
        done(makeError(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception in SignCommand::Private::slotMicAlgDetermined"));
    }
}

void EchoCommand::slotInputReadyRead()
{
    const std::shared_ptr<QIODevice> in = inputs().at(0)->ioDevice();
    Q_ASSERT(in);

    QByteArray buffer;
    buffer.resize(in->bytesAvailable());
    const qint64 read = in->read(buffer.data(), buffer.size());
    if (read == -1) {
        done(makeError(GPG_ERR_EIO));
        return;
    }
    if (read == 0 || (!in->isSequential() && read == in->size())) {
        in->close();
    }

    buffer.resize(read);
    d->buffer += buffer;

    slotOutputBytesWritten();
}

void EchoCommand::slotOutputBytesWritten()
{
    const std::shared_ptr<QIODevice> out = outputs().at(0)->ioDevice();
    Q_ASSERT(out);

    if (!d->buffer.isEmpty()) {
        if (out->bytesToWrite()) {
            return;
        }

        const qint64 written = out->write(d->buffer);
        if (written == -1) {
            done(makeError(GPG_ERR_EIO));
            return;
        }
        d->buffer.remove(0, written);
    }

    if (out->isOpen() && d->buffer.isEmpty() && !inputs().at(0)->ioDevice()->isOpen()) {
        out->close();
        if (!--d->operationsInFlight) {
            done();
        }
    }
}

#include "moc_echocommand.cpp"
