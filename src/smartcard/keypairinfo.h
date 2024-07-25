/*  smartcard/keypairinfo.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QDateTime>

#include <string>

namespace Kleo
{
namespace SmartCard
{
struct KeyPairInfo {
    static KeyPairInfo fromStatusLine(const std::string &s);

    bool canAuthenticate() const;
    bool canCertify() const;
    bool canEncrypt() const;
    bool canSign() const;

    void update(const KeyPairInfo &other);

    bool operator==(const KeyPairInfo &other) const;
    bool operator!=(const KeyPairInfo &other) const;

    std::string keyRef;
    std::string grip;
    std::string usage;
    QDateTime keyTime;
    std::string algorithm;
};
} // namespace Smartcard
} // namespace Kleopatra
