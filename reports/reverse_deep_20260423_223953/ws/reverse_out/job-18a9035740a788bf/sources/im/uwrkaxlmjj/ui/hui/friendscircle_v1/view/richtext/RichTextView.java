package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext;

import android.content.Context;
import android.content.res.TypedArray;
import android.text.DynamicLayout;
import android.text.Layout;
import android.text.Spannable;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.bean.TopicBean;
import im.uwrkaxlmjj.messenger.R;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.ColorTextView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanCreateListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class RichTextView extends ColorTextView {
    private int atColor;
    private long downTime;
    private int emojiSize;
    private int emojiVerticalAlignment;
    private int linkColor;
    private List<FCEntitysResponse> nameList;
    private boolean needNumberShow;
    private boolean needUrlShow;
    private SpanAtUserCallBack spanAtUserCallBack;
    private SpanAtUserCallBack spanAtUserCallBackListener;
    private SpanCreateListener spanCreateListener;
    private SpanTopicCallBack spanTopicCallBack;
    private SpanTopicCallBack spanTopicCallBackListener;
    private SpanUrlCallBack spanUrlCallBack;
    private SpanUrlCallBack spanUrlCallBackListener;
    private int topicColor;
    private List<TopicBean> topicList;

    public RichTextView(Context context) {
        super(context);
        this.topicList = new ArrayList();
        this.nameList = new ArrayList();
        this.atColor = -16776961;
        this.topicColor = -16776961;
        this.linkColor = -16776961;
        this.emojiSize = 0;
        this.needNumberShow = true;
        this.needUrlShow = true;
        this.emojiVerticalAlignment = 0;
        this.spanUrlCallBack = new SpanUrlCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.1
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack
            public void phone(View view, String phone) {
                if (RichTextView.this.spanUrlCallBackListener != null) {
                    RichTextView.this.spanUrlCallBackListener.phone(view, phone);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack
            public void url(View view, String url) {
                if (RichTextView.this.spanUrlCallBackListener != null) {
                    RichTextView.this.spanUrlCallBackListener.url(view, url);
                }
            }
        };
        this.spanAtUserCallBack = new SpanAtUserCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.2
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack
            public void onPresentFragment(BaseFragment baseFragment) {
                if (RichTextView.this.spanAtUserCallBackListener != null) {
                    RichTextView.this.spanAtUserCallBackListener.onPresentFragment(baseFragment);
                }
            }
        };
        this.spanTopicCallBack = new SpanTopicCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.3
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack
            public void onClick(View view, TopicBean TopicBean) {
                if (RichTextView.this.spanTopicCallBackListener != null) {
                    RichTextView.this.spanTopicCallBackListener.onClick(view, TopicBean);
                }
            }
        };
        init(context, null);
    }

    public RichTextView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.topicList = new ArrayList();
        this.nameList = new ArrayList();
        this.atColor = -16776961;
        this.topicColor = -16776961;
        this.linkColor = -16776961;
        this.emojiSize = 0;
        this.needNumberShow = true;
        this.needUrlShow = true;
        this.emojiVerticalAlignment = 0;
        this.spanUrlCallBack = new SpanUrlCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.1
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack
            public void phone(View view, String phone) {
                if (RichTextView.this.spanUrlCallBackListener != null) {
                    RichTextView.this.spanUrlCallBackListener.phone(view, phone);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack
            public void url(View view, String url) {
                if (RichTextView.this.spanUrlCallBackListener != null) {
                    RichTextView.this.spanUrlCallBackListener.url(view, url);
                }
            }
        };
        this.spanAtUserCallBack = new SpanAtUserCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.2
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack
            public void onPresentFragment(BaseFragment baseFragment) {
                if (RichTextView.this.spanAtUserCallBackListener != null) {
                    RichTextView.this.spanAtUserCallBackListener.onPresentFragment(baseFragment);
                }
            }
        };
        this.spanTopicCallBack = new SpanTopicCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.3
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack
            public void onClick(View view, TopicBean TopicBean) {
                if (RichTextView.this.spanTopicCallBackListener != null) {
                    RichTextView.this.spanTopicCallBackListener.onClick(view, TopicBean);
                }
            }
        };
        init(context, attrs);
    }

    public RichTextView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.topicList = new ArrayList();
        this.nameList = new ArrayList();
        this.atColor = -16776961;
        this.topicColor = -16776961;
        this.linkColor = -16776961;
        this.emojiSize = 0;
        this.needNumberShow = true;
        this.needUrlShow = true;
        this.emojiVerticalAlignment = 0;
        this.spanUrlCallBack = new SpanUrlCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.1
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack
            public void phone(View view, String phone) {
                if (RichTextView.this.spanUrlCallBackListener != null) {
                    RichTextView.this.spanUrlCallBackListener.phone(view, phone);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack
            public void url(View view, String url) {
                if (RichTextView.this.spanUrlCallBackListener != null) {
                    RichTextView.this.spanUrlCallBackListener.url(view, url);
                }
            }
        };
        this.spanAtUserCallBack = new SpanAtUserCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.2
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack
            public void onPresentFragment(BaseFragment baseFragment) {
                if (RichTextView.this.spanAtUserCallBackListener != null) {
                    RichTextView.this.spanAtUserCallBackListener.onPresentFragment(baseFragment);
                }
            }
        };
        this.spanTopicCallBack = new SpanTopicCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.RichTextView.3
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack
            public void onClick(View view, TopicBean TopicBean) {
                if (RichTextView.this.spanTopicCallBackListener != null) {
                    RichTextView.this.spanTopicCallBackListener.onClick(view, TopicBean);
                }
            }
        };
        init(context, attrs);
    }

    private void init(Context context, AttributeSet attrs) {
        if (!isInEditMode() && attrs != null) {
            TypedArray array = context.obtainStyledAttributes(attrs, R.styleable.RichTextView);
            this.needNumberShow = array.getBoolean(5, false);
            this.needUrlShow = array.getBoolean(6, false);
            this.atColor = array.getColor(0, -16776961);
            this.topicColor = array.getColor(12, -16776961);
            this.linkColor = array.getColor(3, -16776961);
            this.emojiSize = array.getInteger(1, 0);
            this.emojiVerticalAlignment = array.getInteger(2, 0);
            array.recycle();
        }
    }

    @Override // android.widget.TextView, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        StaticLayout layout = null;
        Field field = null;
        try {
            Field staticField = DynamicLayout.class.getDeclaredField("sStaticLayout");
            staticField.setAccessible(true);
            layout = (StaticLayout) staticField.get(DynamicLayout.class);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e2) {
            e2.printStackTrace();
        }
        if (layout != null) {
            try {
                field = StaticLayout.class.getDeclaredField("mMaximumVisibleLineCount");
                field.setAccessible(true);
                field.setInt(layout, getMaxLines());
            } catch (IllegalAccessException e3) {
                e3.printStackTrace();
            } catch (NoSuchFieldException e4) {
                e4.printStackTrace();
            }
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        if (layout != null && field != null) {
            try {
                field.setInt(layout, Integer.MAX_VALUE);
            } catch (IllegalAccessException e5) {
                e5.printStackTrace();
            }
        }
    }

    @Override // android.widget.TextView, android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        int action = event.getAction();
        if (action == 0) {
            this.downTime = System.currentTimeMillis();
        }
        if (action == 1) {
            long interval = System.currentTimeMillis() - this.downTime;
            int x = (int) event.getX();
            int y = (int) event.getY();
            int x2 = x - getTotalPaddingLeft();
            int y2 = y - getTotalPaddingTop();
            int x3 = x2 + getScrollX();
            int y3 = y2 + getScrollY();
            Layout layout = getLayout();
            int line = layout.getLineForVertical(y3);
            int off = layout.getOffsetForHorizontal(line, x3);
            if (getText() instanceof Spannable) {
                Spannable buffer = (Spannable) getText();
                ClickableSpan[] link = (ClickableSpan[]) buffer.getSpans(off, off, ClickableSpan.class);
                if (link.length != 0 && interval < ViewConfiguration.getLongPressTimeout()) {
                    TextPaint paint = getPaint();
                    int lineStart = layout.getLineStart(line);
                    int lineEnd = layout.getLineEnd(line);
                    CharSequence charSequence = getText().subSequence(lineStart, lineEnd);
                    float v = paint.measureText(charSequence.toString());
                    if (x3 <= v) {
                        link[0].onClick(this);
                        return true;
                    }
                }
            }
        }
        return super.onTouchEvent(event);
    }

    private void resolveRichShow(String content) {
        RichTextBuilder richTextBuilder = new RichTextBuilder(getContext());
        richTextBuilder.setContent(content).setAtColor(this.atColor).setLinkColor(this.linkColor).setTopicColor(this.topicColor).setListUser(this.nameList).setListTopic(this.topicList).setNeedNum(this.needNumberShow).setNeedUrl(this.needUrlShow).setTextView(this).setEmojiSize(this.emojiSize).setSpanAtUserCallBack(this.spanAtUserCallBack).setSpanUrlCallBack(this.spanUrlCallBack).setSpanTopicCallBack(this.spanTopicCallBack).setVerticalAlignment(this.emojiVerticalAlignment).setSpanCreateListener(this.spanCreateListener).build();
    }

    public void setRichTextUser(String text, List<FCEntitysResponse> nameList) {
        setRichText(text, nameList, this.topicList);
    }

    public void setRichTextTopic(String text, List<TopicBean> topicList) {
        setRichText(text, this.nameList, topicList);
    }

    public void setRichText(String text, List<FCEntitysResponse> nameList, List<TopicBean> topicList) {
        if (nameList != null) {
            this.nameList = nameList;
        }
        if (topicList != null) {
            this.topicList = topicList;
        }
        resolveRichShow(text);
    }

    public void setRichText(String text) {
        setRichText(text, this.nameList, this.topicList);
    }

    public boolean isNeedNumberShow() {
        return this.needNumberShow;
    }

    public List<TopicBean> getTopicList() {
        return this.topicList;
    }

    public void setTopicList(List<TopicBean> topicList) {
        this.topicList = topicList;
    }

    public List<FCEntitysResponse> getNameList() {
        return this.nameList;
    }

    public void setNameList(List<FCEntitysResponse> nameList) {
        this.nameList = nameList;
    }

    public void setNeedNumberShow(boolean needNumberShow) {
        this.needNumberShow = needNumberShow;
    }

    public boolean isNeedUrlShow() {
        return this.needUrlShow;
    }

    public void setNeedUrlShow(boolean needUrlShow) {
        this.needUrlShow = needUrlShow;
    }

    public void setSpanUrlCallBackListener(SpanUrlCallBack spanUrlCallBackListener) {
        this.spanUrlCallBackListener = spanUrlCallBackListener;
    }

    public void setSpanAtUserCallBackListener(SpanAtUserCallBack spanAtUserCallBackListener) {
        this.spanAtUserCallBackListener = spanAtUserCallBackListener;
    }

    public void setSpanCreateListener(SpanCreateListener spanCreateListener) {
        this.spanCreateListener = spanCreateListener;
    }

    public void setSpanTopicCallBackListener(SpanTopicCallBack spanTopicCallBackListener) {
        this.spanTopicCallBackListener = spanTopicCallBackListener;
    }

    public int getAtColor() {
        return this.atColor;
    }

    public void setAtColor(int atColor) {
        this.atColor = atColor;
    }

    public int getTopicColor() {
        return this.topicColor;
    }

    public void setTopicColor(int topicColor) {
        this.topicColor = topicColor;
    }

    public int getLinkColor() {
        return this.linkColor;
    }

    public void setLinkColor(int linkColor) {
        this.linkColor = linkColor;
    }

    public void setEmojiSize(int emojiSize) {
        this.emojiSize = emojiSize;
    }

    public void setEmojiVerticalAlignment(int emojiVerticalAlignment) {
        this.emojiVerticalAlignment = emojiVerticalAlignment;
    }

    public int getEmojiVerticalAlignment() {
        return this.emojiVerticalAlignment;
    }
}
