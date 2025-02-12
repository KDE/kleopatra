/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2004, 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleoconfigmodule.h"

#include <QWidget>

#include <memory>

/**
 * "Directory Services" configuration page for kleopatra's configuration dialog
 * The user can configure LDAP servers in this page, to be used for listing/fetching
 * remote certificates in kleopatra.
 */
class DirectoryServicesConfigurationPage : public Kleo::Config::KleoConfigModule
{
    Q_OBJECT
public:
    explicit DirectoryServicesConfigurationPage(QWidget *parent);
    ~DirectoryServicesConfigurationPage() override;

    void load() override;
    void save() override;
    void defaults() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    friend class DirectoryServicesConfigurationPage::Private;
};
