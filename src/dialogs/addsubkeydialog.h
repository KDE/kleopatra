/*
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <Libkleo/KeyUsage>

#include <QDialog>

#include <gpgme++/key.h>

#include <memory.h>

namespace Kleo
{
namespace Dialogs
{

class AddSubkeyDialog : public QDialog
{
    Q_OBJECT
public:
    explicit AddSubkeyDialog(const GpgME::Key &parent, QWidget *p = nullptr);
    ~AddSubkeyDialog() override;

    KeyUsage usage() const;
    QString algo() const;
    QDate expires() const;

private:
    class Private;
    std::unique_ptr<Private> d;

    bool unlimitedValidityIsAllowed() const;
    void setKeyType(const QString &algorithm);
    void loadDefaults();
    void loadDefaultKeyType();
    void setExpiryDate(QDate date);
    QDate forceDateIntoAllowedRange(QDate date) const;
    void loadAlgorithms();
    void replaceEntry(const QString &before, const QString &after);
};

}
}
