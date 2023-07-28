/* -*- mode: c++; c-basic-offset:4 -*-
    utils/keys.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <gpgme++/key.h>

class QDate;

namespace Kleo
{

struct CertificatePair {
    GpgME::Key openpgp;
    GpgME::Key cms;
};

/** Returns true if \p signature is a self-signature. */
bool isSelfSignature(const GpgME::UserID::Signature &signature);

/**
 * Returns true if the most recent self-signature of \p userId is a revocation
 * signature or if it has expired.
 */
bool isRevokedOrExpired(const GpgME::UserID &userId);

/**
 * Returns true if \p key can be used to certify user IDs, i.e. if the key
 * has the required capability and if the secret key of the (primary)
 * certification subkey is available in the keyring or on a smart card.
 */
bool canCreateCertifications(const GpgME::Key &key);

/**
 * Returns true if the key \p key can be certified, i.e. it is an OpenPGP key
 * which is neither revoked nor expired and which has at least one user ID
 * that is neither revoked nor expired.
 */
bool canBeCertified(const GpgME::Key &key);

/**
 * Returns true if \p key can be used for operations requiring the secret key,
 * i.e. if the secret key of the primary key pair is available in the keyring
 * or on a smart card.
 *
 * \note Key::hasSecret() also returns true if a secret key stub, e.g. of an
 * offline key, is available in the keyring.
 */
bool canBeUsedForSecretKeyOperations(const GpgME::Key &key);

/**
 * Returns true if \p userId can be revoked, i.e. if it isn't the last valid
 * user ID of an OpenPGP key.
 */
bool canRevokeUserID(const GpgME::UserID &userId);

/**
 * Returns true if the secret key of the primary key pair of \p key is stored
 * in the keyring.
 */
bool isSecretKeyStoredInKeyRing(const GpgME::Key &key);

/**
 * Returns true if any keys suitable for certifying user IDs are available in
 * the keyring or on a smart card.
 *
 * \sa canCreateCertifications
 */
bool userHasCertificationKey();

enum CertificationRevocationFeasibility {
    CertificationCanBeRevoked = 0,
    CertificationNotMadeWithOwnKey,
    CertificationIsSelfSignature,
    CertificationIsRevocation,
    CertificationIsExpired,
    CertificationIsInvalid,
    CertificationKeyNotAvailable,
};

/**
 * Checks if the user can revoke the given \p certification.
 */
CertificationRevocationFeasibility userCanRevokeCertification(const GpgME::UserID::Signature &certification);

/**
 * Returns true if the user can revoke any of the certifications of the \p userId.
 *
 * \sa userCanRevokeCertification
 */
bool userCanRevokeCertifications(const GpgME::UserID &userId);

/**
 * Returns true, if the user ID \p userID belongs to the key \p key.
 */
bool userIDBelongsToKey(const GpgME::UserID &userID, const GpgME::Key &key);

/**
 * Returns a unary predicate to check if a user ID belongs to the key \p key.
 */
inline auto userIDBelongsToKey(const GpgME::Key &key)
{
    return [key](const GpgME::UserID &userID) {
        return userIDBelongsToKey(userID, key);
    };
}

/**
 * Returns true, if the two user IDs \p lhs and \p rhs are equal.
 *
 * Equality means that both user IDs belong to the same key, contain identical
 * text, and have the same creation date (i.e. the creation date of the first
 * self-signature is the same).
 */
bool userIDsAreEqual(const GpgME::UserID &lhs, const GpgME::UserID &rhs);

}
