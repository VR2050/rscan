package im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.text.TextPaint;
import android.text.TextUtils;
import android.view.View;
import android.widget.TextView;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan;

/* JADX INFO: loaded from: classes5.dex */
public class FCLinkSpan extends LinkSpan {
    private Context context;
    private String url;

    public FCLinkSpan(Context context, String url, int color, SpanUrlCallBack spanUrlCallBack) {
        super(url, color, spanUrlCallBack);
        this.context = context;
        this.url = url;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan, android.text.style.ClickableSpan
    public void onClick(View view) {
        super.onClick(view);
        if (view instanceof TextView) {
            ((TextView) view).setHighlightColor(0);
        }
        if (!TextUtils.isEmpty(this.url) && this.context != null) {
            if ((this.url.contains("tel:") && TextUtils.isDigitsOnly(this.url.replace("tel:", ""))) || TextUtils.isDigitsOnly(this.url)) {
                this.context.startActivity(new Intent("android.intent.action.DIAL", Uri.parse(this.url)));
                return;
            }
            if (Browser.isInternalUrl(this.url, null)) {
                Browser.openUrl(this.context, this.url, true);
                return;
            }
            String realUrl = this.url;
            if (!realUrl.contains("://") && (!realUrl.startsWith(DefaultWebClient.HTTP_SCHEME) || !realUrl.startsWith(DefaultWebClient.HTTPS_SCHEME))) {
                realUrl = DefaultWebClient.HTTP_SCHEME + realUrl;
            }
            Intent intent = new Intent();
            intent.setAction("android.intent.action.VIEW");
            Uri content_url = Uri.parse(realUrl);
            intent.setData(content_url);
            this.context.startActivity(intent);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan, android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint ds) {
        super.updateDrawState(ds);
    }
}
