/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QDialog>

#include <gpgme++/key.h>

#include <memory>
#include <vector>

namespace Kleo
{
namespace SmartCard
{
struct AlgorithmInfo;
}

class GenCardKeyDialog : public QDialog
{
    Q_OBJECT

public:
    struct KeyParams {
        QString name;
        QString email;
        QString comment;
        std::string algorithm;
        bool backup;
    };

    enum KeyAttribute {
        // clang-format off
        NoKeyAttributes = 0,
        KeyOwnerName    = 1,
        KeyOwnerEmail   = 2,
        KeyComment      = 4,
        KeyAlgorithm    = 8,
        LocalKeyBackup  = 16,

        _AllKeyAttributes_Helper,
        AllKeyAttributes = 2 * (_AllKeyAttributes_Helper - 1) - 1
        // clang-format on
    };

    Q_DECLARE_FLAGS(KeyAttributes, KeyAttribute)

    explicit GenCardKeyDialog(KeyAttributes requiredAttributes, QWidget *parent = nullptr);

    KeyParams getKeyParams() const;

    void setSupportedAlgorithms(const std::vector<SmartCard::AlgorithmInfo> &algorithms, const std::string &defaultAlgo);

private:
    class Private;
    std::shared_ptr<Private> d;
};
} // namespace Kleo
