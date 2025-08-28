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

class CreateCSRDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateCSRDialog(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~CreateCSRDialog() override;

    void setName(const QString &name);
    QString name() const;

    void setEmail(const QString &email);
    QString email() const;

    void setKeyParameters(const KeyParameters &parameters);
    KeyParameters keyParameters() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

} // namespace Kleo
