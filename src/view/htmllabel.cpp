/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "htmllabel.h"

#include "anchorcache_p.h"

#include <QAccessible>
#include <QDesktopServices>

using namespace Kleo;

class HtmlLabel::Private
{
    HtmlLabel *q;

public:
    explicit Private(HtmlLabel *qq)
        : q{qq}
    {
    }

    void updateText(const QString &newText = {});

    AnchorCache mAnchorCache;
    QColor linkColor;
};

void HtmlLabel::Private::updateText(const QString &newText)
{
    static const QString styleTemplate{QLatin1StringView{"<style type=\"text/css\">a {color: %1;}</style>"}};

    if (newText.isEmpty() && q->text().isEmpty()) {
        return;
    }

    const auto styleTag = styleTemplate.arg(linkColor.isValid() ? linkColor.name() : q->palette().link().color().name());
    if (newText.isEmpty()) {
        q->setText(styleTag + q->text().mid(styleTag.size()));
    } else {
        q->setText(styleTag + newText);
    }
    mAnchorCache.setText(q->text());
}

HtmlLabel::HtmlLabel(QWidget *parent)
    : HtmlLabel{{}, parent}
{
}

HtmlLabel::HtmlLabel(const QString &html, QWidget *parent)
    : QLabel{parent}
    , d{new Private{this}}
{
    setTextFormat(Qt::RichText);
    setTextInteractionFlags(Qt::TextBrowserInteraction);
    setHtml(html);
}

HtmlLabel::~HtmlLabel() = default;

void HtmlLabel::setHtml(const QString &html)
{
    if (html.isEmpty()) {
        clear();
        d->mAnchorCache.clear();
        return;
    }
    d->updateText(html);
}

void HtmlLabel::setLinkColor(const QColor &color)
{
    d->linkColor = color;
    d->updateText();
}

int HtmlLabel::numberOfAnchors() const
{
    return d->mAnchorCache.size();
}

QString HtmlLabel::anchorText(int index) const
{
    if (index >= 0 && index < d->mAnchorCache.size()) {
        return d->mAnchorCache[index].text;
    }
    return {};
}

QString HtmlLabel::anchorHref(int index) const
{
    if (index >= 0 && index < d->mAnchorCache.size()) {
        return d->mAnchorCache[index].href;
    }
    return {};
}

void HtmlLabel::activateAnchor(int index)
{
    // based on QWidgetTextControlPrivate::activateLinkUnderCursor
    if (index < 0 || index >= d->mAnchorCache.size()) {
        return;
    }
    const auto &anchor = d->mAnchorCache[index];
    if (anchor.href.isEmpty()) {
        return;
    }
    if (hasFocus()) {
        // move cursor just before the anchor and clear the selection
        setSelection(anchor.start, 0);
        // focus the anchor
        focusNextPrevChild(true);
    } else {
        // clear the selection moving the cursor just after the anchor
        setSelection(anchor.end, 0);
    }
    if (openExternalLinks()) {
        QDesktopServices::openUrl(QUrl{anchor.href});
    } else {
        Q_EMIT linkActivated(anchor.href);
    }
}

int HtmlLabel::selectedAnchor() const
{
    return d->mAnchorCache.findAnchor(selectionStart());
}

bool HtmlLabel::focusNextPrevChild(bool next)
{
    const bool result = QLabel::focusNextPrevChild(next);
    if (hasFocus() && QAccessible::isActive()) {
        const int anchorIndex = selectedAnchor();
        if (anchorIndex >= 0) {
            QAccessibleEvent focusEvent(this, QAccessible::Focus);
            focusEvent.setChild(anchorIndex);
            QAccessible::updateAccessibility(&focusEvent);
        }
    }
    return result;
}

#include "moc_htmllabel.cpp"
