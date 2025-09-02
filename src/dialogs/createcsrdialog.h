/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>

namespace Kleo
{
class KeyParameters;
class KeyUsage;

class CreateCSRDialog : public QDialog
{
    Q_OBJECT

public:
    enum Field {
        Algorithm = 0x01,
        Usage = 0x02,
    };
    Q_DECLARE_FLAGS(Fields, Field)

    explicit CreateCSRDialog(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~CreateCSRDialog() override;

    void setName(const QString &name);
    QString name() const;

    void setEmail(const QString &email);
    QString email() const;

    void setAlgorithm(const QString &algorithm);
    QString algorithm() const;

    void setUsage(KeyUsage usage);
    KeyUsage usage() const;

    void setKeyParameters(const KeyParameters &parameters);
    KeyParameters keyParameters() const;

    void setReadOnly(Fields fields);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(CreateCSRDialog::Fields);

} // namespace Kleo
