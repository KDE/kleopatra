/* -*- mode: c++; c-basic-offset:4 -*-
    crypto/gui/wizardpage.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include <memory>

class KGuiItem;

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class Wizard;

class WizardPage : public QWidget
{
    friend class ::Kleo::Crypto::Gui::Wizard;
    Q_OBJECT
public:
    explicit WizardPage(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~WizardPage() override;

    virtual bool isComplete() const = 0;

    bool isCommitPage() const;
    void setCommitPage(bool commitPage);

    bool autoAdvance() const;
    void setAutoAdvance(bool enabled);

    QString title() const;
    void setTitle(const QString &title);

    QString subTitle() const;
    void setSubTitle(const QString &subTitle);

    QString explanation() const;
    void setExplanation(const QString &explanation);

    KGuiItem customNextButton() const;
    void setCustomNextButton(const KGuiItem &item);

Q_SIGNALS:
    void completeChanged();
    void explanationChanged();
    void titleChanged();
    void subTitleChanged();
    void autoAdvanceChanged();
    void windowTitleChanged(const QString &title);

protected:
    virtual bool onNext();

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
}
