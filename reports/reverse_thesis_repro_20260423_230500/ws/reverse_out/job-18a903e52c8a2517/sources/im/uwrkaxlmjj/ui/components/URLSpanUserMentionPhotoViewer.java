package im.uwrkaxlmjj.ui.components;

import android.text.TextPaint;

/* JADX INFO: loaded from: classes5.dex */
public class URLSpanUserMentionPhotoViewer extends URLSpanUserMention {
    public URLSpanUserMentionPhotoViewer(String url, boolean isOutOwner) {
        super(url, 2);
    }

    @Override // im.uwrkaxlmjj.ui.components.URLSpanUserMention, im.uwrkaxlmjj.ui.components.URLSpanNoUnderline, android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint ds) {
        super.updateDrawState(ds);
        ds.setColor(-1);
        ds.setUnderlineText(false);
    }
}
