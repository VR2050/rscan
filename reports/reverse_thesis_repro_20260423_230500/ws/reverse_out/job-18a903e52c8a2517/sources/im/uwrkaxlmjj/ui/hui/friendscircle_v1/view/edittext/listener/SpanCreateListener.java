package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener;

import android.content.Context;
import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.bean.TopicBean;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickTopicSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan;

/* JADX INFO: loaded from: classes5.dex */
public interface SpanCreateListener {
    ClickAtUserSpan getCustomClickAtUserSpan(Context context, FCEntitysResponse fCEntitysResponse, int i, SpanAtUserCallBack spanAtUserCallBack);

    ClickTopicSpan getCustomClickTopicSpan(Context context, TopicBean topicBean, int i, SpanTopicCallBack spanTopicCallBack);

    LinkSpan getCustomLinkSpan(Context context, String str, int i, SpanUrlCallBack spanUrlCallBack);
}
