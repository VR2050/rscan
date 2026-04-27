package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span;

import android.text.TextPaint;
import android.text.TextUtils;
import android.text.style.ClickableSpan;
import android.view.View;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack;

/* JADX INFO: loaded from: classes5.dex */
public class LinkSpan extends ClickableSpan {
    private int color;
    private SpanUrlCallBack spanUrlCallBack;
    private String url;

    public LinkSpan(String url, int color, SpanUrlCallBack spanUrlCallBack) {
        this.url = url;
        this.spanUrlCallBack = spanUrlCallBack;
        this.color = color;
    }

    @Override // android.text.style.ClickableSpan
    public void onClick(View widget) {
        if ((this.url.contains("tel:") && TextUtils.isDigitsOnly(this.url.replace("tel:", ""))) || TextUtils.isDigitsOnly(this.url)) {
            SpanUrlCallBack spanUrlCallBack = this.spanUrlCallBack;
            if (spanUrlCallBack != null) {
                spanUrlCallBack.phone(widget, this.url);
                return;
            }
            return;
        }
        SpanUrlCallBack spanUrlCallBack2 = this.spanUrlCallBack;
        if (spanUrlCallBack2 != null) {
            spanUrlCallBack2.url(widget, this.url);
        }
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint ds) {
        ds.setColor(this.color);
        ds.setUnderlineText(false);
    }
}
