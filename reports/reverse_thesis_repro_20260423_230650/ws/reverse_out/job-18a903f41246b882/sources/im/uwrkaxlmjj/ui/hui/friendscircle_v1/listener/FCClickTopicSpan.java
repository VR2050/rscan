package im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener;

import android.text.TextPaint;
import com.bjz.comm.net.bean.TopicBean;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickTopicSpan;

/* JADX INFO: loaded from: classes5.dex */
public class FCClickTopicSpan extends ClickTopicSpan {
    public FCClickTopicSpan(TopicBean topicBean, int color, SpanTopicCallBack spanTopicCallBack) {
        super(topicBean, color, spanTopicCallBack);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan, android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint ds) {
        super.updateDrawState(ds);
    }
}
