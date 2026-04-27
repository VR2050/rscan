package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span;

import android.view.View;
import com.bjz.comm.net.bean.TopicBean;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack;

/* JADX INFO: loaded from: classes5.dex */
public class ClickTopicSpan extends ClickAtUserSpan {
    private SpanTopicCallBack spanTopicCallBack;
    private TopicBean topicModel;

    public ClickTopicSpan(TopicBean topicModel, int color, SpanTopicCallBack spanTopicCallBack) {
        super(null, color, null);
        this.topicModel = topicModel;
        this.spanTopicCallBack = spanTopicCallBack;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan, android.text.style.ClickableSpan
    public void onClick(View view) {
        super.onClick(view);
        SpanTopicCallBack spanTopicCallBack = this.spanTopicCallBack;
        if (spanTopicCallBack != null) {
            spanTopicCallBack.onClick(view, this.topicModel);
        }
    }
}
