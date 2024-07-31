/*  smartcard/openpgpcard.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "card.h"

namespace Kleo
{
namespace SmartCard
{
struct AlgorithmInfo;
struct KeyPairInfo;

/** Class to work with OpenPGP smartcards or compatible tokens */
class OpenPGPCard : public Card
{
public:
    explicit OpenPGPCard(const Card &card);

    static const std::string AppName;

    static std::string pgpSigKeyRef();
    static std::string pgpEncKeyRef();
    static std::string pgpAuthKeyRef();

    static std::string pinKeyRef();
    static std::string adminPinKeyRef();
    static std::string resetCodeKeyRef();

    static const std::vector<KeyPairInfo> &supportedKeys();

    /**
     * Returns an algorithm name for the algorithm \p algorithm that is suitable
     * for passing to scdaemon for the card slot specified by \p keyRef.
     *
     * For example, it maps "curve25519" to either "ed25519" or "cv25519".
     */
    static std::string getAlgorithmName(const std::string &algorithm, const std::string &keyRef);

    /**
     * Sets the algorithms supported by this smart card to \p algorithms.
     * The following values for algorithms are allowed:
     *   brainpoolP256r1, brainpoolP384r1, brainpoolP512r1,
     *   curve25519,
     *   nistp256, nistp384, nistp521,
     *   rsa2048, rsa3072, rsa4096.
     */
    void setSupportedAlgorithms(const std::vector<std::string> &algorithms);

    std::string pubkeyUrl() const;

    /**
     * Returns a list of algorithm IDs and corresponding display names.
     *
     * \note: You have to use getAlgorithmName to map the algorithm ID to
     *        an algorithm name suitable for a certain card slot.
     */
    std::vector<AlgorithmInfo> supportedAlgorithms() const;

    /**
     * Returns true, if the algorithm with ID \p algorithm is supported by this
     * smart card. Otherwise, returns false.
     */
    bool isSupportedAlgorithm(const std::string &algorithm) const;

private:
    OpenPGPCard(const OpenPGPCard &card) = default;

    OpenPGPCard *clone() const override;

private:
    std::vector<std::string> mAlgorithms;
};
} // namespace Smartcard
} // namespace Kleopatra
