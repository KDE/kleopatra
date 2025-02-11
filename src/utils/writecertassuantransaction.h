/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <gpgme++/data.h>
#include <gpgme++/defaultassuantransaction.h>

class QByteArray;

namespace Kleo
{

class WriteCertAssuanTransaction : public GpgME::DefaultAssuanTransaction
{
public:
    explicit WriteCertAssuanTransaction(const QByteArray &certificateData);
    ~WriteCertAssuanTransaction() override;

private:
    GpgME::Data inquire(const char *name, const char *args, GpgME::Error &err) override;

private:
    GpgME::Data mCertData;
};

} // namespace Kleo
