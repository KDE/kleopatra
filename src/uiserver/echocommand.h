/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"
#include <QObject>

namespace Kleo
{

/*!
  \brief GnuPG UI Server command for testing

  <h3>Usage</h3>

  \code
  ECHO [--inquire <keyword>] [--nohup]
  \endcode

  <h3>Description</h3>

  The ECHO command is a simple tool for testing. If a bulk input
  channel has been set up by the client, ECHO will read data from
  it, and pipe it right back into the bulk output channel. It is
  an error for an input channel to exist without an output
  channel.

  ECHO will also send back any non-option command line arguments
  in a status message. If the --inquire command line option has
  been given, ECHO will inquire with that keyword, and send the
  received data back on the status channel.
*/
class EchoCommand : public QObject, public AssuanCommandMixin<EchoCommand>
{
    Q_OBJECT
public:
    EchoCommand();
    ~EchoCommand() override;

    static const char *staticName()
    {
        return "ECHO";
    }

private:
    int doStart() override;
    void doCanceled() override;

private Q_SLOTS:
    void slotInquireData(int, const QByteArray &);
    void slotInputReadyRead();
    void slotOutputBytesWritten();

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
