/*  smartcard/keypairinfo.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keypairinfo.h"

#include <QString>
#include <QStringList>
#include <QTimeZone>

using namespace Kleo::SmartCard;
using namespace Qt::Literals::StringLiterals;

// static
KeyPairInfo KeyPairInfo::fromStatusLine(const std::string &s)
{
    // The format of a KEYPAIRINFO line is
    //   KEYPAIRINFO <hexgrip> <keyref> [usage] [keytime] [algostr]
    // The string s does not contain the leading "KEYPAIRINFO ".
    KeyPairInfo info;
    const auto values = QString::fromStdString(s).split(QLatin1Char(' '));
    if (values.size() < 2) {
        return info;
    }
    info.grip = values[0].toStdString();
    info.keyRef = values[1].toStdString();
    if (values.size() >= 3) {
        info.usage = values[2].toStdString();
    }
    if (values.size() >= 4 && !values[3].isEmpty() && values[3] != "-"_L1) {
        bool ok;
        const qint64 secondsSinceEpoch = values[3].toLongLong(&ok);
        if (ok) {
            info.keyTime = QDateTime::fromSecsSinceEpoch(secondsSinceEpoch, QTimeZone::utc());
        }
    }
    if (values.size() >= 5) {
        info.algorithm = values[4].toStdString();
    }
    return info;
}

bool KeyPairInfo::canAuthenticate() const
{
    return usage.find('a') != std::string::npos;
}

bool KeyPairInfo::canCertify() const
{
    return usage.find('c') != std::string::npos;
}

bool KeyPairInfo::canEncrypt() const
{
    return usage.find('e') != std::string::npos;
}

bool KeyPairInfo::canSign() const
{
    return usage.find('s') != std::string::npos;
}

void KeyPairInfo::update(const KeyPairInfo &other)
{
    Q_ASSERT(keyRef == other.keyRef);
    if (keyRef != other.keyRef) {
        return;
    }
    if (grip != other.grip) {
        // reset all infos if the grip changed
        grip = other.grip;
        usage = std::string();
        keyTime = QDateTime{};
        algorithm = std::string();
    }
    // now update all infos from other's infos unless other's infos are empty or not specified
    if (!other.usage.empty() && other.usage != "-") {
        usage = other.usage;
    }
    if (other.keyTime.isValid()) {
        keyTime = other.keyTime;
    }
    if (!other.algorithm.empty() && other.algorithm != "-") {
        algorithm = other.algorithm;
    }
}

// C++20: Replace with defaulted equality operator
bool KeyPairInfo::operator==(const KeyPairInfo &other) const
{
    return keyRef == other.keyRef && grip == other.grip && usage == other.usage && keyTime == other.keyTime && algorithm == other.algorithm;
}

// C++20: Remove
bool KeyPairInfo::operator!=(const KeyPairInfo &other) const
{
    return !operator==(other);
}
