/*  view/cardkeysview.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <Libkleo/Predicates>

#include <QWidget>

#include <set>
#include <string>
#include <vector>

namespace GpgME
{
class Key;
class KeyListResult;
}

namespace Kleo
{
class KeyTreeView;
class ProgressOverlay;

namespace SmartCard
{
class Card;
}

class CardKeysView : public QWidget
{
    Q_OBJECT
public:
    explicit CardKeysView(QWidget *parent = nullptr);
    ~CardKeysView() override;

    void setCard(const SmartCard::Card *card);

private:
    void loadCertificates();
    void ensureCertificatesAreValidated();
    void startCertificateValidation(const std::vector<GpgME::Key> &certificates);
    void certificateValidationDone(const GpgME::KeyListResult &result, const std::vector<GpgME::Key> &keys);
    void learnCard();

private:
    std::string mSerialNumber;
    std::string mAppName;
    std::vector<GpgME::Key> mCertificates;

    using KeySet = std::set<GpgME::Key, _detail::ByFingerprint<std::less>>;
    KeySet mValidatedCertificates;

    KeyTreeView *mTreeView = nullptr;
    ProgressOverlay *mTreeViewOverlay = nullptr;
};
} // namespace Kleo
