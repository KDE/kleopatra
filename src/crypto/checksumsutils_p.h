/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleopatra_debug.h"

#include <QRegularExpression>

namespace Kleo
{
class ChecksumDefinition;
}

namespace ChecksumsUtils
{
#ifdef Q_OS_UNIX
// Can we use QAbstractFileEngine::caseSensitive()?
static const Qt::CaseSensitivity fs_cs = Qt::CaseSensitive;

static const QRegularExpression::PatternOption s_regex_cs = QRegularExpression::NoPatternOption;
#else
static const Qt::CaseSensitivity fs_cs = Qt::CaseInsensitive;
static const QRegularExpression::PatternOption s_regex_cs = QRegularExpression::CaseInsensitiveOption;
#endif

std::vector<QRegularExpression> get_patterns(const std::vector<std::shared_ptr<Kleo::ChecksumDefinition>> &checksumDefinitions);

struct matches_any {
    const std::vector<QRegularExpression> m_regexps;
    explicit matches_any(const std::vector<QRegularExpression> &regexps)
        : m_regexps(regexps)
    {
    }
    bool operator()(const QString &s) const
    {
        return std::any_of(m_regexps.cbegin(), m_regexps.cend(), [&s](const QRegularExpression &rx) {
            return rx.match(s).hasMatch();
        });
    }
};

struct File {
    QString name;
    QByteArray checksum;
    bool binary;
};

std::vector<File> parse_sum_file(const QString &fileName);

std::shared_ptr<Kleo::ChecksumDefinition> filename2definition(const QString &fileName,
                                                              const std::vector<std::shared_ptr<Kleo::ChecksumDefinition>> &checksumDefinitions);

} // namespace ChecksumsUtils
