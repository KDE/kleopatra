/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/gui/resolverecipientspage.h>

#include <KMime/Types>

#include <QHash>

class QComboBox;
class QLabel;
class QListWidget;
class QListWidgetItem;
#include <QStringList>
class QToolButton;

class Kleo::Crypto::Gui::ResolveRecipientsPage::ListWidget : public QWidget
{
    Q_OBJECT
public:
    explicit ListWidget(QWidget *parent = nullptr, Qt::WindowFlags flags = {});
    ~ListWidget() override;

    void addEntry(const QString &id, const QString &name);
    void addEntry(const KMime::Types::Mailbox &mbox);
    void addEntry(const QString &id, const QString &name, const KMime::Types::Mailbox &mbox);

    void removeEntry(const QString &id);
    QStringList selectedEntries() const;
    void setCertificates(const QString &id, const std::vector<GpgME::Key> &pgpCerts, const std::vector<GpgME::Key> &cmsCerts);
    GpgME::Key selectedCertificate(const QString &id) const;
    GpgME::Key selectedCertificate(const QString &id, GpgME::Protocol prot) const;
    KMime::Types::Mailbox mailbox(const QString &id) const;
    QStringList identifiers() const;
    void setProtocol(GpgME::Protocol prot);
    void showSelectionDialog(const QString &id);

    enum Role {
        IdRole = Qt::UserRole,
    };

Q_SIGNALS:
    void selectionChanged();
    void completeChanged();

private Q_SLOTS:
    void onSelectionChange();

private:
    QListWidget *m_listWidget;

    QHash<QString, ItemWidget *> widgets;
    QHash<QString, QListWidgetItem *> items;
    GpgME::Protocol m_protocol;
};

class Kleo::Crypto::Gui::ResolveRecipientsPage::ItemWidget : public QWidget
{
    Q_OBJECT
public:
    explicit ItemWidget(const QString &id, const QString &name, const KMime::Types::Mailbox &mbox, QWidget *parent = nullptr, Qt::WindowFlags flags = {});
    ~ItemWidget() override;

    QString id() const;
    KMime::Types::Mailbox mailbox() const;
    void setCertificates(const std::vector<GpgME::Key> &pgp, const std::vector<GpgME::Key> &cms);
    GpgME::Key selectedCertificate() const;
    GpgME::Key selectedCertificate(GpgME::Protocol prot) const;
    std::vector<GpgME::Key> certificates() const;
    void setProtocol(GpgME::Protocol protocol);
    void setSelected(bool selected);
    bool isSelected() const;

public Q_SLOTS:
    void showSelectionDialog();

Q_SIGNALS:
    void changed();

private:
    void addCertificateToComboBox(const GpgME::Key &key);
    void resetCertificates();
    void selectCertificateInComboBox(const GpgME::Key &key);
    void updateVisibility();

private:
    QString m_id;
    KMime::Types::Mailbox m_mailbox;
    QLabel *m_nameLabel;
    QLabel *m_certLabel;
    QComboBox *m_certCombo;
    QToolButton *m_selectButton;
    GpgME::Protocol m_protocol;
    QHash<GpgME::Protocol, GpgME::Key> m_selectedCertificates;
    std::vector<GpgME::Key> m_pgp, m_cms;
    bool m_selected;
};
