/* -*- mode: c++; c-basic-offset:4 -*-
    mainwindow.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <KXmlGuiWindow>

#include <memory>

namespace Kleo
{
class KeyListController;
class DocAction;
}

class MainWindow : public KXmlGuiWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~MainWindow() override;

    Kleo::KeyListController *keyListController();

    static std::unique_ptr<Kleo::DocAction> createSymmetricGuideAction(QObject *parent);

public Q_SLOTS:
    void importCertificatesFromFile(const QStringList &files);
    void exportWindow();
    void unexportWindow();

protected:
    QByteArray savedGeometry;

    void closeEvent(QCloseEvent *e) override;
    void showEvent(QShowEvent *e) override;
    void hideEvent(QHideEvent *e) override;
    void dragEnterEvent(QDragEnterEvent *) override;
    void dropEvent(QDropEvent *) override;
    void readProperties(const KConfigGroup &cg) override;
    void saveProperties(KConfigGroup &cg) override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void closeAndQuit())
    Q_PRIVATE_SLOT(d, void configureToolbars())
    Q_PRIVATE_SLOT(d, void editKeybindings())
    Q_PRIVATE_SLOT(d, void slotConfigCommitted())
    Q_PRIVATE_SLOT(d, void slotContextMenuRequested(QAbstractItemView *, QPoint))
    Q_PRIVATE_SLOT(d, void slotFocusQuickSearch())
    Q_PRIVATE_SLOT(d, void showPadView())
};
