/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "anchorcache_p.h"

#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>

void AnchorCache::setText(const QString &text)
{
    mText = text;
    mAnchorsValid = false;
}

void AnchorCache::clear()
{
    mText.clear();
    mAnchorsValid = false;
}

int AnchorCache::size() const
{
    return anchors().size();
}

const AnchorData &AnchorCache::operator[](int index) const
{
    return anchors()[index];
}

int AnchorCache::findAnchor(int start) const
{
    anchors(); // ensure that the anchor cache is valid
    auto it = std::find_if(std::cbegin(mAnchors), std::cend(mAnchors), [start](const auto &anchor) {
        return anchor.start == start;
    });
    if (it != std::cend(mAnchors)) {
        return std::distance(std::cbegin(mAnchors), it);
    }
    return -1;
}

const std::vector<AnchorData> &AnchorCache::anchors() const
{
    if (mAnchorsValid) {
        return mAnchors;
    }

    mAnchors.clear();
    if (mText.isEmpty()) {
        return mAnchors;
    }

    QTextDocument doc;
    doc.setHtml(mText);

    // taken from QWidgetTextControl::setFocusToNextOrPreviousAnchor and QWidgetTextControl::findNextPrevAnchor
    for (QTextBlock block = doc.begin(); block.isValid(); block = block.next()) {
        QTextBlock::Iterator it = block.begin();

        while (!it.atEnd()) {
            const QTextFragment fragment = it.fragment();
            const QTextCharFormat fmt = fragment.charFormat();

            if (fmt.isAnchor() && fmt.hasProperty(QTextFormat::AnchorHref)) {
                const int anchorStart = fragment.position();
                const QString anchorHref = fmt.anchorHref();
                int anchorEnd = -1;

                // find next non-anchor fragment
                for (; !it.atEnd(); ++it) {
                    const QTextFragment fragment = it.fragment();
                    const QTextCharFormat fmt = fragment.charFormat();

                    if (!fmt.isAnchor() || fmt.anchorHref() != anchorHref) {
                        anchorEnd = fragment.position();
                        break;
                    }
                }

                if (anchorEnd == -1) {
                    anchorEnd = block.position() + block.length() - 1;
                }

                QTextCursor cursor{&doc};
                cursor.setPosition(anchorStart);
                cursor.setPosition(anchorEnd, QTextCursor::KeepAnchor);
                QString anchorText = cursor.selectedText();
                mAnchors.push_back({anchorStart, anchorEnd, anchorText, anchorHref});
            } else {
                ++it;
            }
        }
    }

    mAnchorsValid = true;
    return mAnchors;
}
