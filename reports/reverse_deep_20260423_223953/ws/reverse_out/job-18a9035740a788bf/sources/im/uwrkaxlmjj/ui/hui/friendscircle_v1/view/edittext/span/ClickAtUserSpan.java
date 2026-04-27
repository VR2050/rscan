package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span;

import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.view.View;
import com.bjz.comm.net.bean.FCEntitysResponse;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack;

/* JADX INFO: loaded from: classes5.dex */
public class ClickAtUserSpan extends ClickableSpan {
    private int color;

    public ClickAtUserSpan(FCEntitysResponse FCEntitysResponse, int color, SpanAtUserCallBack spanClickCallBack) {
        this.color = color;
    }

    @Override // android.text.style.ClickableSpan
    public void onClick(View view) {
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint ds) {
        ds.setColor(this.color);
        ds.setUnderlineText(false);
    }
}
