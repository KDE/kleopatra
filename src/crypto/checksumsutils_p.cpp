/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "checksumsutils_p.h"
#include <Libkleo/ChecksumDefinition>

#include <QFile>
#include <QTextStream>

std::vector<QRegularExpression> ChecksumsUtils::get_patterns(const std::vector<std::shared_ptr<Kleo::ChecksumDefinition>> &checksumDefinitions)
{
    std::vector<QRegularExpression> result;
    for (const auto &cd : checksumDefinitions) {
        if (!cd) {
            continue;
        }
        const QStringList &patterns = cd->patterns();
        result.reserve(result.size() + patterns.size());
        std::transform(patterns.cbegin(), patterns.cend(), std::back_inserter(result), [](const QString &pattern) {
            return QRegularExpression(QRegularExpression::anchoredPattern(pattern), s_regex_cs);
        });
    }

    return result;
}

static QString decode(const QString &encoded)
{
    QString decoded;
    decoded.reserve(encoded.size());
    bool shift = false;
    for (const QChar ch : encoded)
        if (shift) {
            switch (ch.toLatin1()) {
            case '\\':
                decoded += QLatin1Char('\\');
                break;
            case 'n':
                decoded += QLatin1Char('\n');
                break;
            default:
                qCDebug(KLEOPATRA_LOG) << "invalid escape sequence" << '\\' << ch << "(interpreted as '" << ch << "')";
                decoded += ch;
                break;
            }
            shift = false;
        } else {
            if (ch == QLatin1Char('\\')) {
                shift = true;
            } else {
                decoded += ch;
            }
        }
    return decoded;
}

std::vector<ChecksumsUtils::File> ChecksumsUtils::parse_sum_file(const QString &fileName)
{
    std::vector<File> files;
    QFile f(fileName);
    if (!f.open(QIODevice::ReadOnly)) {
        return {};
    }

    QTextStream s(&f);
    static const QRegularExpression rx(QRegularExpression::anchoredPattern(uR"((\\?)([a-f0-9A-F]+) ([ *])([^\\n]+)\\n*)"));
    while (!s.atEnd()) {
        const QString line = s.readLine();
        QRegularExpressionMatch match = rx.match(line);
        if (!match.hasMatch()) {
            continue;
        }

        Q_ASSERT(!match.capturedView(4).endsWith(QLatin1Char('\n')));
        const File file = {
            match.capturedView(1) == QLatin1Char('\\') ? decode(match.captured(4)) : match.captured(4),
            match.capturedView(2).toLatin1(),
            match.capturedView(3) == QLatin1Char('*'),
        };
        files.push_back(file);
    }

    return files;
}

std::shared_ptr<Kleo::ChecksumDefinition> ChecksumsUtils::filename2definition(const QString &fileName,
                                                                              const std::vector<std::shared_ptr<Kleo::ChecksumDefinition>> &checksumDefinitions)
{
    auto matchFileName = [&fileName](const std::shared_ptr<Kleo::ChecksumDefinition> &cd) {
        if (!cd) {
            return false;
        }

        const QStringList &patterns = cd->patterns();
        return std::any_of(patterns.cbegin(), patterns.cend(), [&fileName](const QString &pattern) {
            const QRegularExpression re(QRegularExpression::anchoredPattern(pattern), s_regex_cs);
            return re.match(fileName).hasMatch();
        });
    };

    auto it = std::find_if(checksumDefinitions.cbegin(), checksumDefinitions.cend(), matchFileName);

    return it != checksumDefinitions.cend() ? *it : std::shared_ptr<Kleo::ChecksumDefinition>{};
}
