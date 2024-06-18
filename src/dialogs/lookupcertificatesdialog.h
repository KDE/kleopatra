/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/lookupcertificatesdialog.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>
#include <vector>

#include <gpgme++/key.h>

struct KeyWithOrigin {
    GpgME::Key key;
    GpgME::Key::Origin origin;
};

namespace Kleo
{
namespace Dialogs
{

class LookupCertificatesDialog : public QDialog
{
    Q_OBJECT
public:
    enum QueryMode {
        AnyQuery, //< any query is allowed
        EmailQuery, //< only email queries are allowed
    };

    explicit LookupCertificatesDialog(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~LookupCertificatesDialog() override;

    void setQueryMode(QueryMode mode);
    QueryMode queryMode() const;

    void setCertificates(const std::vector<KeyWithOrigin> &certs);
    std::vector<KeyWithOrigin> selectedCertificates() const;

    void setPassive(bool passive);
    bool isPassive() const;
    void setSearchText(const QString &text);
    QString searchText() const;

    void setOverlayText(const QString &text);
    QString overlayText() const;

Q_SIGNALS:
    void searchTextChanged(const QString &text);
    void saveAsRequested(const std::vector<GpgME::Key> &certs);
    void importRequested(const std::vector<KeyWithOrigin> &certs);
    void detailsRequested(const GpgME::Key &certs);

public Q_SLOTS:
    void accept() override;

protected:
    void keyPressEvent(QKeyEvent *event) override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotSearchTextChanged())
    Q_PRIVATE_SLOT(d, void slotSearchClicked())
    Q_PRIVATE_SLOT(d, void slotSelectionChanged())
    Q_PRIVATE_SLOT(d, void slotDetailsClicked())
    Q_PRIVATE_SLOT(d, void slotSaveAsClicked())
};

}
}
