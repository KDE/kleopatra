/* -*- mode: c++; c-basic-offset:4 -*-
    utils/validation.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QValidator>

#include <memory>

class QString;

namespace Kleo
{
namespace Validation
{

enum Flags {
    Optional,
    Required,
};

/**
 * Creates a validator with restrictions imposed by the regular expression \p regExp.
 * If \p flags is \c Optional then empty values are also accepted.
 */
std::shared_ptr<QValidator> regularExpressionValidator(const QString &regExp, Flags flags = Required);

std::shared_ptr<QValidator> email(Flags flags = Required);
/**
 * Creates a validator for the name part of the user ID of an OpenPGP key with
 * restrictions that are necessary for usage with the edit-key interface.
 */
std::shared_ptr<QValidator> pgpName(Flags flags = Required);
/**
 * Creates a validator for the name part of the user ID of an OpenPGP key with
 * less restrictions than \ref pgpName.
 */
std::shared_ptr<QValidator> simpleName(Flags flags = Required);

std::shared_ptr<QValidator> email(const QString &additionalRegExp, Flags flags = Required);
/**
 * Creates a validator for the name part of the user ID of an OpenPGP key with
 * restrictions that are necessary for usage with the edit-key interface, and
 * with additional restrictions imposed by \p additionalRegExp.
 */
std::shared_ptr<QValidator> pgpName(const QString &additionalRegExp, Flags flags = Required);
/**
 * Creates a validator for the name part of the user ID of an OpenPGP key with
 * less restrictions than \ref pgpName, but with additional restrictions imposed
 * by \p additionalRegExp.
 */
std::shared_ptr<QValidator> simpleName(const QString &additionalRegExp, Flags flags = Required);

template<class Validator>
class TrimmingValidator : public Validator
{
public:
    using Validator::Validator;

    QValidator::State validate(QString &str, int &pos) const override
    {
        auto trimmed = str.trimmed();
        auto posCopy = pos;
        return Validator::validate(trimmed, posCopy);
    }
};

template<class Validator>
class EmptyIsAcceptableValidator : public Validator
{
public:
    using Validator::Validator;

    QValidator::State validate(QString &str, int &pos) const override
    {
        if (str.isEmpty()) {
            return QValidator::Acceptable;
        }
        return Validator::validate(str, pos);
    }
};
}
}
