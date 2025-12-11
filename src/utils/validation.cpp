/* -*- mode: c++; c-basic-offset:4 -*-
    utils/validation.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "validation.h"

#include <utils/multivalidator.h>

#include <KEmailAddress>

#include "kleopatra_debug.h"

#include <QRegularExpression>

using namespace Kleo;

namespace
{

class EMailValidator : public QValidator
{
public:
    EMailValidator()
        : QValidator{}
    {
    }

    State validate(QString &str, int &pos) const override
    {
        Q_UNUSED(pos)
        if (KEmailAddress::isValidSimpleAddress(str)) {
            return Acceptable;
        }
        return Intermediate;
    }
};

}

std::shared_ptr<QValidator> Validation::regularExpressionValidator(const QString &regexp, Flags flags)
{
    if (flags & Validation::Required) {
        return std::make_shared<TrimmingValidator<QRegularExpressionValidator>>(QRegularExpression{regexp});
    } else {
        return std::make_shared<TrimmingValidator<EmptyIsAcceptableValidator<QRegularExpressionValidator>>>(QRegularExpression{regexp});
    }
}

std::shared_ptr<QValidator> Validation::email(Flags flags)
{
    if (flags & Required) {
        return std::make_shared<TrimmingValidator<EMailValidator>>();
    } else {
        return std::make_shared<TrimmingValidator<EmptyIsAcceptableValidator<EMailValidator>>>();
    }
}

std::shared_ptr<QValidator> Validation::email(const QString &addRX, Flags flags)
{
    return MultiValidator::create({email(flags), regularExpressionValidator(addRX, flags)});
}

std::shared_ptr<QValidator> Validation::pgpName(Flags flags)
{
    // this regular expression is modeled after gnupg/g10/keygen.c:ask_user_id:
    static const QString name_rx{QLatin1String{"[^0-9<>][^<>@]{4,}"}};
    return regularExpressionValidator(name_rx, flags);
}

std::shared_ptr<QValidator> Validation::pgpName(const QString &addRX, Flags flags)
{
    return MultiValidator::create({pgpName(flags), regularExpressionValidator(addRX, flags)});
}

std::shared_ptr<QValidator> Validation::simpleName(Flags flags)
{
    static const QString name_rx{QLatin1String{"[^<>@]*"}};
    return std::shared_ptr<QValidator>{regularExpressionValidator(name_rx, flags)};
}

std::shared_ptr<QValidator> Validation::simpleName(const QString &additionalRegExp, Flags flags)
{
    return MultiValidator::create({simpleName(flags), regularExpressionValidator(additionalRegExp, flags)});
}
