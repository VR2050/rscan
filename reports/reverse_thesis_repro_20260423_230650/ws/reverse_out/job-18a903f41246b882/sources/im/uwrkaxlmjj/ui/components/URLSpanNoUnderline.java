package im.uwrkaxlmjj.ui.components;

import android.net.Uri;
import android.text.TextPaint;
import android.text.style.URLSpan;
import android.view.View;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.ui.components.TextStyleSpan;

/* JADX INFO: loaded from: classes5.dex */
public class URLSpanNoUnderline extends URLSpan {
    private TextStyleSpan.TextStyleRun style;

    public URLSpanNoUnderline(String url) {
        this(url, null);
    }

    public URLSpanNoUnderline(String url, TextStyleSpan.TextStyleRun run) {
        super(url != null ? url.replace((char) 8238, ' ') : url);
        this.style = run;
    }

    @Override // android.text.style.URLSpan, android.text.style.ClickableSpan
    public void onClick(View widget) {
        String url = getURL();
        if (url.startsWith("@")) {
            Uri uri = Uri.parse("https://m12345.com/" + url.substring(1));
            Browser.openUrl(widget.getContext(), uri);
            return;
        }
        Browser.openUrl(widget.getContext(), url);
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint p) {
        super.updateDrawState(p);
        TextStyleSpan.TextStyleRun textStyleRun = this.style;
        if (textStyleRun != null) {
            textStyleRun.applyStyle(p);
        } else {
            p.setUnderlineText(false);
        }
    }
}
