/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QString>

#include <vector>

struct AnchorData {
    int start;
    int end;
    QString text;
    QString href;
};

class AnchorCache
{
public:
    void setText(const QString &text);
    void clear();

    int size() const;
    const AnchorData &operator[](int index) const;
    int findAnchor(int start) const;

private:
    const std::vector<AnchorData> &anchors() const;

private:
    QString mText;
    mutable bool mAnchorsValid = false;
    mutable std::vector<AnchorData> mAnchors;
};
