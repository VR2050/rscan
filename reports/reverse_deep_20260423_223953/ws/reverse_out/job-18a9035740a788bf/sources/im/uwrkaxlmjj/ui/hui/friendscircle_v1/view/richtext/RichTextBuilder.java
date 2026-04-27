package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext;

import android.content.Context;
import android.text.Spannable;
import android.text.method.MovementMethod;
import android.widget.TextView;
import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.bean.TopicBean;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickTopicSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class RichTextBuilder {
    private Context context;
    private List<TopicBean> listTopic;
    private List<FCEntitysResponse> listUser;
    private SpanAtUserCallBack spanAtUserCallBack;
    private SpanCreateListener spanCreateListener;
    private SpanTopicCallBack spanTopicCallBack;
    private SpanUrlCallBack spanUrlCallBack;
    private TextView textView;
    private String content = "";
    private int atColor = -16776961;
    private int topicColor = -16776961;
    private int linkColor = -16776961;
    private int emojiSize = 0;
    private int verticalAlignment = 0;
    private boolean needNum = false;
    private boolean needUrl = false;

    public RichTextBuilder(Context context) {
        this.context = context;
    }

    public RichTextBuilder setContent(String content) {
        this.content = content;
        return this;
    }

    public RichTextBuilder setListUser(List<FCEntitysResponse> listUser) {
        this.listUser = listUser;
        return this;
    }

    public RichTextBuilder setListTopic(List<TopicBean> listTopic) {
        this.listTopic = listTopic;
        return this;
    }

    public RichTextBuilder setTextView(TextView textView) {
        this.textView = textView;
        return this;
    }

    public RichTextBuilder setAtColor(int atColor) {
        this.atColor = atColor;
        return this;
    }

    public RichTextBuilder setTopicColor(int topicColor) {
        this.topicColor = topicColor;
        return this;
    }

    public RichTextBuilder setLinkColor(int linkColor) {
        this.linkColor = linkColor;
        return this;
    }

    public RichTextBuilder setNeedNum(boolean needNum) {
        this.needNum = needNum;
        return this;
    }

    public RichTextBuilder setNeedUrl(boolean needUrl) {
        this.needUrl = needUrl;
        return this;
    }

    public RichTextBuilder setSpanAtUserCallBack(SpanAtUserCallBack spanAtUserCallBack) {
        this.spanAtUserCallBack = spanAtUserCallBack;
        return this;
    }

    public RichTextBuilder setSpanUrlCallBack(SpanUrlCallBack spanUrlCallBack) {
        this.spanUrlCallBack = spanUrlCallBack;
        return this;
    }

    public RichTextBuilder setSpanTopicCallBack(SpanTopicCallBack spanTopicCallBack) {
        this.spanTopicCallBack = spanTopicCallBack;
        return this;
    }

    public RichTextBuilder setEmojiSize(int emojiSize) {
        this.emojiSize = emojiSize;
        return this;
    }

    public RichTextBuilder setVerticalAlignment(int verticalAlignment) {
        this.verticalAlignment = verticalAlignment;
        return this;
    }

    public RichTextBuilder setSpanCreateListener(SpanCreateListener spanCreateListener) {
        this.spanCreateListener = spanCreateListener;
        return this;
    }

    public Spannable buildSpan(ITextViewShow iTextViewShow) {
        Context context = this.context;
        if (context == null) {
            throw new IllegalStateException("context could not be null.");
        }
        return TextCommonUtils.getAllSpanText(context, this.content, this.listUser, this.listTopic, iTextViewShow, this.atColor, this.linkColor, this.topicColor, this.needNum, this.needUrl, this.spanAtUserCallBack, this.spanUrlCallBack, this.spanTopicCallBack);
    }

    public void build() {
        if (this.context == null) {
            throw new IllegalStateException("context could not be null.");
        }
        if (this.textView == null) {
            throw new IllegalStateException("textView could not be null.");
        }
        ITextViewShow iTextViewShow = new ITextViewShow() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextBuilder.1
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public void setText(CharSequence charSequence) {
                RichTextBuilder.this.textView.setText(charSequence);
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public CharSequence getText() {
                return RichTextBuilder.this.textView.getText();
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public void setMovementMethod(MovementMethod movementMethod) {
                RichTextBuilder.this.textView.setMovementMethod(movementMethod);
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public void setAutoLinkMask(int flag) {
                RichTextBuilder.this.textView.setAutoLinkMask(flag);
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public ClickAtUserSpan getCustomClickAtUserSpan(Context context, FCEntitysResponse userModel, int color, SpanAtUserCallBack spanClickCallBack) {
                if (RichTextBuilder.this.spanCreateListener != null) {
                    return RichTextBuilder.this.spanCreateListener.getCustomClickAtUserSpan(context, userModel, color, spanClickCallBack);
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public ClickTopicSpan getCustomClickTopicSpan(Context context, TopicBean topicModel, int color, SpanTopicCallBack spanTopicCallBack) {
                if (RichTextBuilder.this.spanCreateListener != null) {
                    return RichTextBuilder.this.spanCreateListener.getCustomClickTopicSpan(context, topicModel, color, spanTopicCallBack);
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public LinkSpan getCustomLinkSpan(Context context, String url, int color, SpanUrlCallBack spanUrlCallBack) {
                if (RichTextBuilder.this.spanCreateListener != null) {
                    return RichTextBuilder.this.spanCreateListener.getCustomLinkSpan(context, url, color, spanUrlCallBack);
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public int emojiSize() {
                return RichTextBuilder.this.emojiSize;
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow
            public int verticalAlignment() {
                return RichTextBuilder.this.verticalAlignment;
            }
        };
        Spannable spannable = TextCommonUtils.getAllSpanText(this.context, this.content, this.listUser, this.listTopic, iTextViewShow, this.atColor, this.linkColor, this.topicColor, this.needNum, this.needUrl, this.spanAtUserCallBack, this.spanUrlCallBack, this.spanTopicCallBack);
        this.textView.setText(spannable);
    }
}
