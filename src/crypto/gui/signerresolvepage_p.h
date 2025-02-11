/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <gpgme++/global.h>

class QButtonGroup;
class QCheckBox;
class QLabel;

#include <map>
#include <set>
#include <vector>

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class AbstractSigningProtocolSelectionWidget : public QWidget
{
    Q_OBJECT
public:
    explicit AbstractSigningProtocolSelectionWidget(QWidget *parent = nullptr, Qt::WindowFlags flags = {});
    virtual void setProtocolChecked(GpgME::Protocol protocol, bool checked) = 0;
    virtual bool isProtocolChecked(GpgME::Protocol protocol) const = 0;
    virtual std::set<GpgME::Protocol> checkedProtocols() const = 0;
    virtual void setCertificate(GpgME::Protocol protocol, const GpgME::Key &key) = 0;

Q_SIGNALS:
    void userSelectionChanged();
};

class SigningProtocolSelectionWidget : public AbstractSigningProtocolSelectionWidget
{
    Q_OBJECT
public:
    explicit SigningProtocolSelectionWidget(QWidget *parent = nullptr, Qt::WindowFlags flags = {});
    void setProtocolChecked(GpgME::Protocol protocol, bool checked) override;
    bool isProtocolChecked(GpgME::Protocol protocol) const override;
    std::set<GpgME::Protocol> checkedProtocols() const override;
    void setCertificate(GpgME::Protocol protocol, const GpgME::Key &key) override;

    void setExclusive(bool exclusive);
    bool isExclusive() const;

private:
    QCheckBox *button(GpgME::Protocol p) const;
    std::map<GpgME::Protocol, QCheckBox *> m_buttons;
    QButtonGroup *m_buttonGroup;
};

class ReadOnlyProtocolSelectionWidget : public AbstractSigningProtocolSelectionWidget
{
    Q_OBJECT
public:
    explicit ReadOnlyProtocolSelectionWidget(QWidget *parent = nullptr, Qt::WindowFlags flags = {});
    void setProtocolChecked(GpgME::Protocol protocol, bool checked) override;
    bool isProtocolChecked(GpgME::Protocol protocol) const override;
    std::set<GpgME::Protocol> checkedProtocols() const override;
    void setCertificate(GpgME::Protocol protocol, const GpgME::Key &key) override;

private:
    QLabel *label(GpgME::Protocol p) const;
    std::map<GpgME::Protocol, QLabel *> m_labels;
};

}
}
}
