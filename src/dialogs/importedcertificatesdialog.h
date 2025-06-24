// SPDX-FileCopyrightText: 2025 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QDialog>

#include "commands/importcertificatescommand_p.h"

class ImportedCertificatesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ImportedCertificatesDialog(const std::vector<ImportResultData> &res, QWidget *parent = nullptr);
};
