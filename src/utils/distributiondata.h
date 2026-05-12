/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QByteArray>
#include <QString>

#include <optional>

struct DistributionData {
    bool isValid = false;

    std::optional<QString> displayName;
    std::optional<QString> productName;
    std::optional<QString> componentName;
    std::optional<QString> shortDescription;
    std::optional<QString> homepage;
    std::optional<QString> bugAddress;
    std::optional<QString> version;
    std::optional<QString> otherText;
    std::optional<QString> copyrightStatement;
    std::optional<QString> desktopFileName;

    std::optional<QString> uidComment;
    std::optional<QString> statusLine;
};
