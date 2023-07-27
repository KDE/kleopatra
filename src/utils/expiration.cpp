/* -*- mode: c++; c-basic-offset:4 -*-
    utils/expiration.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "expiration.h"

#include <settings.h>

#include <KDateComboBox>
#include <KLocalizedString>

QDate Kleo::maximumAllowedDate()
{
    static const QDate maxAllowedDate{2106, 2, 5};
    return maxAllowedDate;
}

QDate Kleo::minimumExpirationDate()
{
    return expirationDateRange().minimum;
}

QDate Kleo::maximumExpirationDate()
{
    return expirationDateRange().maximum;
}

Kleo::DateRange Kleo::expirationDateRange()
{
    Kleo::DateRange range;

    const auto settings = Kleo::Settings{};
    const auto today = QDate::currentDate();

    const auto minimumExpiry = std::max(1, settings.validityPeriodInDaysMin());
    range.minimum = std::min(today.addDays(minimumExpiry), maximumAllowedDate());

    const auto maximumExpiry = settings.validityPeriodInDaysMax();
    if (maximumExpiry >= 0) {
        range.maximum = std::min(std::max(today.addDays(maximumExpiry), range.minimum), maximumAllowedDate());
    }

    return range;
}

QDate Kleo::defaultExpirationDate(Kleo::ExpirationOnUnlimitedValidity onUnlimitedValidity)
{
    QDate expirationDate;

    const auto settings = Kleo::Settings{};
    const auto defaultExpirationInDays = settings.validityPeriodInDays();
    if (defaultExpirationInDays > 0) {
        expirationDate = QDate::currentDate().addDays(defaultExpirationInDays);
    } else if (defaultExpirationInDays < 0 || onUnlimitedValidity == ExpirationOnUnlimitedValidity::InternalDefaultExpiration) {
        expirationDate = QDate::currentDate().addYears(3);
    }

    const auto allowedRange = expirationDateRange();
    expirationDate = std::max(expirationDate, allowedRange.minimum);
    if (allowedRange.maximum.isValid()) {
        expirationDate = std::min(expirationDate, allowedRange.maximum);
    }

    return expirationDate;
}

bool Kleo::isValidExpirationDate(const QDate &date)
{
    const auto allowedRange = expirationDateRange();
    if (date.isValid()) {
        return (date >= allowedRange.minimum //
                && (!allowedRange.maximum.isValid() || date <= allowedRange.maximum));
    } else {
        return !allowedRange.maximum.isValid();
    }
}

static QString dateToString(const QDate &date, QWidget *widget)
{
    // workaround for QLocale using "yy" way too often for years
    // stolen from KDateComboBox
    auto locale = widget ? widget->locale() : QLocale{};
    const auto dateFormat = (locale.dateFormat(QLocale::ShortFormat) //
                                    .replace(QLatin1String{"yy"}, QLatin1String{"yyyy"})
                                    .replace(QLatin1String{"yyyyyyyy"}, QLatin1String{"yyyy"}));
    return locale.toString(date, dateFormat);
}

static QString validityPeriodHint(const Kleo::DateRange &dateRange, QWidget *widget)
{
    // the minimum date is always valid
    if (dateRange.maximum.isValid()) {
        if (dateRange.maximum == dateRange.minimum) {
            return i18nc("@info", "The validity period cannot be changed.");
        } else {
            return i18nc("@info ... between <a date> and <another date>.", "Enter a date between %1 and %2.",
                         dateToString(dateRange.minimum, widget), dateToString(dateRange.maximum, widget));
        }
    } else {
        return i18nc("@info ... between <a date> and <another date>.", "Enter a date between %1 and %2.",
                     dateToString(dateRange.minimum, widget), dateToString(Kleo::maximumAllowedDate(), widget));
    }
}

QString Kleo::validityPeriodHint()
{
    return ::validityPeriodHint(expirationDateRange(), nullptr);
}

void Kleo::setUpExpirationDateComboBox(KDateComboBox *dateCB)
{
    const auto dateRange = expirationDateRange();
    dateCB->setMinimumDate(dateRange.minimum);
    dateCB->setMaximumDate(dateRange.maximum);
    if (dateRange.minimum == dateRange.maximum) {
        // validity period is a fixed number of days
        dateCB->setEnabled(false);
    }
    dateCB->setToolTip(validityPeriodHint(dateRange, dateCB));
}
