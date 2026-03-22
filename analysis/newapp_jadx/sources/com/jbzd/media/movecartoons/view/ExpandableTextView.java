package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.text.DynamicLayout;
import android.text.Layout;
import android.text.Selection;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.text.style.StyleSpan;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatTextView;
import com.jbzd.media.movecartoons.R$styleable;
import java.lang.reflect.Field;

/* loaded from: classes2.dex */
public class ExpandableTextView extends AppCompatTextView {
    private static final String CLASS_NAME_LISTENER_INFO = "android.view.View$ListenerInfo";
    private static final String CLASS_NAME_VIEW = "android.view.View";
    private static final String ELLIPSIS_HINT = "..";
    private static final String GAP_TO_EXPAND_HINT = " ";
    private static final String GAP_TO_SHRINK_HINT = " ";
    private static final int MAX_LINES_ON_SHRINK = 2;
    private static final boolean SHOW_TO_EXPAND_HINT = true;
    private static final boolean SHOW_TO_SHRINK_HINT = true;
    public static final int STATE_EXPAND = 1;
    public static final int STATE_SHRINK = 0;
    private static final boolean TOGGLE_ENABLE = true;
    private static final int TO_EXPAND_HINT_COLOR = -13330213;
    private static final int TO_EXPAND_HINT_COLOR_BG_PRESSED = 1436129689;
    private static final int TO_SHRINK_HINT_COLOR = -1618884;
    private static final int TO_SHRINK_HINT_COLOR_BG_PRESSED = 1436129689;
    private TextView.BufferType mBufferType;
    private int mCurrState;
    private String mEllipsisHint;
    private ExpandableClickListener mExpandableClickListener;
    private int mFutureTextViewWidth;
    private String mGapToExpandHint;
    private String mGapToShrinkHint;
    private Layout mLayout;
    private int mLayoutWidth;
    private int mMaxLinesOnShrink;
    private OnExpandListener mOnExpandListener;
    private CharSequence mOrigText;
    private boolean mShowToExpandHint;
    private boolean mShowToShrinkHint;
    private int mTextLineCount;
    private TextPaint mTextPaint;
    private String mToExpandHint;
    private int mToExpandHintColor;
    private int mToExpandHintColorBgPressed;
    private String mToShrinkHint;
    private int mToShrinkHintColor;
    private int mToShrinkHintColorBgPressed;
    private boolean mToggleEnable;
    private TouchableSpan mTouchableSpan;

    public class ExpandableClickListener implements View.OnClickListener {
        private ExpandableClickListener() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            ExpandableTextView.this.toggle();
        }
    }

    public class LinkTouchMovementMethod extends LinkMovementMethod {
        private TouchableSpan mPressedSpan;

        public LinkTouchMovementMethod() {
        }

        private TouchableSpan getPressedSpan(TextView textView, Spannable spannable, MotionEvent motionEvent) {
            int x = (int) motionEvent.getX();
            int y = (int) motionEvent.getY();
            int totalPaddingLeft = x - textView.getTotalPaddingLeft();
            int totalPaddingTop = y - textView.getTotalPaddingTop();
            int scrollX = textView.getScrollX() + totalPaddingLeft;
            int scrollY = textView.getScrollY() + totalPaddingTop;
            Layout layout = textView.getLayout();
            int offsetForHorizontal = layout.getOffsetForHorizontal(layout.getLineForVertical(scrollY), scrollX);
            TouchableSpan[] touchableSpanArr = (TouchableSpan[]) spannable.getSpans(offsetForHorizontal, offsetForHorizontal, TouchableSpan.class);
            if (touchableSpanArr.length > 0) {
                return touchableSpanArr[0];
            }
            return null;
        }

        @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
        public boolean onTouchEvent(TextView textView, Spannable spannable, MotionEvent motionEvent) {
            if (motionEvent.getAction() == 0) {
                TouchableSpan pressedSpan = getPressedSpan(textView, spannable, motionEvent);
                this.mPressedSpan = pressedSpan;
                if (pressedSpan != null) {
                    pressedSpan.setPressed(true);
                    Selection.setSelection(spannable, spannable.getSpanStart(this.mPressedSpan), spannable.getSpanEnd(this.mPressedSpan));
                }
            } else if (motionEvent.getAction() == 2) {
                TouchableSpan pressedSpan2 = getPressedSpan(textView, spannable, motionEvent);
                TouchableSpan touchableSpan = this.mPressedSpan;
                if (touchableSpan != null && pressedSpan2 != touchableSpan) {
                    touchableSpan.setPressed(false);
                    this.mPressedSpan = null;
                    Selection.removeSelection(spannable);
                }
            } else {
                TouchableSpan touchableSpan2 = this.mPressedSpan;
                if (touchableSpan2 != null) {
                    touchableSpan2.setPressed(false);
                    super.onTouchEvent(textView, spannable, motionEvent);
                }
                this.mPressedSpan = null;
                Selection.removeSelection(spannable);
            }
            return true;
        }
    }

    public interface OnExpandListener {
        void onExpand(ExpandableTextView expandableTextView);

        void onShrink(ExpandableTextView expandableTextView);
    }

    public class TouchableSpan extends ClickableSpan {
        private boolean mIsPressed;

        private TouchableSpan() {
        }

        @Override // android.text.style.ClickableSpan
        public void onClick(View view) {
            if (ExpandableTextView.this.hasOnClickListeners()) {
                ExpandableTextView expandableTextView = ExpandableTextView.this;
                if (expandableTextView.getOnClickListener(expandableTextView) instanceof ExpandableClickListener) {
                    return;
                }
            }
            ExpandableTextView.this.toggle();
        }

        public void setPressed(boolean z) {
            this.mIsPressed = z;
        }

        @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
        public void updateDrawState(TextPaint textPaint) {
            super.updateDrawState(textPaint);
            int i2 = ExpandableTextView.this.mCurrState;
            if (i2 == 0) {
                textPaint.setColor(Color.parseColor("#ff6a00"));
                textPaint.bgColor = this.mIsPressed ? ExpandableTextView.this.mToExpandHintColorBgPressed : 0;
            } else if (i2 == 1) {
                textPaint.setColor(Color.parseColor("#ff6a00"));
                textPaint.bgColor = this.mIsPressed ? ExpandableTextView.this.mToShrinkHintColorBgPressed : 0;
            }
            textPaint.setUnderlineText(false);
        }
    }

    public ExpandableTextView(Context context) {
        super(context);
        this.mGapToExpandHint = " ";
        this.mGapToShrinkHint = " ";
        this.mToggleEnable = true;
        this.mShowToExpandHint = true;
        this.mShowToShrinkHint = true;
        this.mMaxLinesOnShrink = 2;
        this.mToExpandHintColor = TO_EXPAND_HINT_COLOR;
        this.mToShrinkHintColor = TO_SHRINK_HINT_COLOR;
        this.mToExpandHintColorBgPressed = 1436129689;
        this.mToShrinkHintColorBgPressed = 1436129689;
        this.mCurrState = 0;
        this.mBufferType = TextView.BufferType.NORMAL;
        this.mTextLineCount = -1;
        this.mLayoutWidth = 0;
        this.mFutureTextViewWidth = 0;
        init();
    }

    private String getContentOfString(String str) {
        return str == null ? "" : str;
    }

    private int getLengthOfString(String str) {
        if (str == null) {
            return 0;
        }
        return str.length();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public CharSequence getNewTextByConfig() {
        String str;
        int i2;
        int i3;
        int i4;
        if (TextUtils.isEmpty(this.mOrigText)) {
            return this.mOrigText;
        }
        Layout layout = getLayout();
        this.mLayout = layout;
        if (layout != null) {
            this.mLayoutWidth = layout.getWidth();
        }
        if (this.mLayoutWidth <= 0) {
            if (getWidth() == 0) {
                int i5 = this.mFutureTextViewWidth;
                if (i5 == 0) {
                    return this.mOrigText;
                }
                this.mLayoutWidth = (i5 - getPaddingLeft()) - getPaddingRight();
            } else {
                this.mLayoutWidth = (getWidth() - getPaddingLeft()) - getPaddingRight();
            }
        }
        this.mTextPaint = getPaint();
        this.mTextLineCount = -1;
        int i6 = this.mCurrState;
        if (i6 != 0) {
            if (i6 != 1) {
                return this.mOrigText;
            }
            if (!this.mShowToShrinkHint) {
                return this.mOrigText;
            }
            DynamicLayout dynamicLayout = new DynamicLayout(this.mOrigText, this.mTextPaint, this.mLayoutWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            this.mLayout = dynamicLayout;
            int lineCount = dynamicLayout.getLineCount();
            this.mTextLineCount = lineCount;
            if (lineCount <= this.mMaxLinesOnShrink) {
                return this.mOrigText;
            }
            SpannableStringBuilder append = new SpannableStringBuilder(this.mOrigText).append((CharSequence) this.mGapToShrinkHint).append((CharSequence) this.mToShrinkHint);
            append.setSpan(new StyleSpan(1), append.length() - getLengthOfString(this.mToShrinkHint), append.length(), 33);
            append.setSpan(this.mTouchableSpan, append.length() - getLengthOfString(this.mToShrinkHint), append.length(), 33);
            return append;
        }
        DynamicLayout dynamicLayout2 = new DynamicLayout(this.mOrigText, this.mTextPaint, this.mLayoutWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
        this.mLayout = dynamicLayout2;
        int lineCount2 = dynamicLayout2.getLineCount();
        this.mTextLineCount = lineCount2;
        if (lineCount2 <= this.mMaxLinesOnShrink) {
            return this.mOrigText;
        }
        int lineEnd = getValidLayout().getLineEnd(this.mMaxLinesOnShrink - 1);
        int lineStart = getValidLayout().getLineStart(this.mMaxLinesOnShrink - 1);
        int lengthOfString = (lineEnd - getLengthOfString(this.mEllipsisHint)) - (this.mShowToExpandHint ? getLengthOfString(this.mToExpandHint) + getLengthOfString(this.mGapToExpandHint) : 0);
        if (lengthOfString > lineStart) {
            lineEnd = lengthOfString;
        }
        int width = getValidLayout().getWidth() - ((int) (this.mTextPaint.measureText(this.mOrigText.subSequence(lineStart, lineEnd).toString()) + 0.5d));
        TextPaint textPaint = this.mTextPaint;
        StringBuilder sb = new StringBuilder();
        sb.append(getContentOfString(this.mEllipsisHint));
        if (this.mShowToExpandHint) {
            str = getContentOfString(this.mToExpandHint) + getContentOfString(this.mGapToExpandHint);
        } else {
            str = "";
        }
        sb.append(str);
        float measureText = textPaint.measureText(sb.toString());
        float f2 = width;
        if (f2 > measureText) {
            int i7 = 0;
            int i8 = 0;
            while (f2 > i7 + measureText && (i4 = lineEnd + (i8 = i8 + 1)) <= this.mOrigText.length()) {
                i7 = (int) (this.mTextPaint.measureText(this.mOrigText.subSequence(lineEnd, i4).toString()) + 0.5d);
            }
            i2 = (i8 - 1) + lineEnd;
        } else {
            int i9 = 0;
            int i10 = 0;
            while (i9 + width < measureText && (i3 = lineEnd + (i10 - 1)) > lineStart) {
                i9 = (int) (this.mTextPaint.measureText(this.mOrigText.subSequence(i3, lineEnd).toString()) + 0.5d);
            }
            i2 = lineEnd + i10;
        }
        SpannableStringBuilder append2 = new SpannableStringBuilder(removeEndLineBreak(this.mOrigText.subSequence(0, i2))).append((CharSequence) this.mEllipsisHint);
        if (this.mShowToExpandHint) {
            append2.append((CharSequence) (getContentOfString(this.mGapToExpandHint) + getContentOfString(this.mToExpandHint)));
            append2.setSpan(new StyleSpan(1), append2.length() - getLengthOfString(this.mToExpandHint), append2.length(), 33);
            append2.setSpan(this.mTouchableSpan, append2.length() - getLengthOfString(this.mToExpandHint), append2.length(), 33);
        }
        return append2;
    }

    private View.OnClickListener getOnClickListenerV(View view) {
        try {
            Field declaredField = Class.forName(CLASS_NAME_VIEW).getDeclaredField("mOnClickListener");
            declaredField.setAccessible(true);
            return (View.OnClickListener) declaredField.get(view);
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    private View.OnClickListener getOnClickListenerV14(View view) {
        Object obj;
        try {
            Field declaredField = Class.forName(CLASS_NAME_VIEW).getDeclaredField("mListenerInfo");
            if (declaredField != null) {
                declaredField.setAccessible(true);
                obj = declaredField.get(view);
            } else {
                obj = null;
            }
            Field declaredField2 = Class.forName(CLASS_NAME_LISTENER_INFO).getDeclaredField("mOnClickListener");
            if (declaredField2 == null || obj == null) {
                return null;
            }
            declaredField2.setAccessible(true);
            return (View.OnClickListener) declaredField2.get(obj);
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    private Layout getValidLayout() {
        Layout layout = this.mLayout;
        return layout != null ? layout : getLayout();
    }

    private void init() {
        this.mTouchableSpan = new TouchableSpan();
        setMovementMethod(new LinkTouchMovementMethod());
        if (TextUtils.isEmpty(this.mEllipsisHint)) {
            this.mEllipsisHint = ELLIPSIS_HINT;
        }
        if (TextUtils.isEmpty(this.mToExpandHint)) {
            this.mToExpandHint = "查看全文";
        }
        if (TextUtils.isEmpty(this.mToShrinkHint)) {
            this.mToShrinkHint = "收起";
        }
        if (this.mToggleEnable) {
            ExpandableClickListener expandableClickListener = new ExpandableClickListener();
            this.mExpandableClickListener = expandableClickListener;
            setOnClickListener(expandableClickListener);
        }
        getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() { // from class: com.jbzd.media.movecartoons.view.ExpandableTextView.1
            @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
            public void onGlobalLayout() {
                ExpandableTextView.this.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                ExpandableTextView expandableTextView = ExpandableTextView.this;
                expandableTextView.setTextInternal(expandableTextView.getNewTextByConfig(), ExpandableTextView.this.mBufferType);
            }
        });
    }

    private void initAttr(Context context, AttributeSet attributeSet) {
        TypedArray obtainStyledAttributes;
        if (attributeSet == null || (obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ExpandableTextView)) == null) {
            return;
        }
        int indexCount = obtainStyledAttributes.getIndexCount();
        for (int i2 = 0; i2 < indexCount; i2++) {
            int index = obtainStyledAttributes.getIndex(i2);
            if (index == 5) {
                this.mMaxLinesOnShrink = obtainStyledAttributes.getInteger(index, 2);
            } else if (index == 0) {
                this.mEllipsisHint = obtainStyledAttributes.getString(index);
            } else if (index == 6) {
                this.mToExpandHint = obtainStyledAttributes.getString(index);
            } else if (index == 10) {
                this.mToShrinkHint = obtainStyledAttributes.getString(index);
            } else if (index == 1) {
                this.mToggleEnable = obtainStyledAttributes.getBoolean(index, true);
            } else if (index == 9) {
                this.mShowToExpandHint = obtainStyledAttributes.getBoolean(index, true);
            } else if (index == 13) {
                this.mShowToShrinkHint = obtainStyledAttributes.getBoolean(index, true);
            } else if (index == 7) {
                this.mToExpandHintColor = obtainStyledAttributes.getInteger(index, TO_EXPAND_HINT_COLOR);
            } else if (index == 11) {
                this.mToShrinkHintColor = obtainStyledAttributes.getInteger(index, TO_SHRINK_HINT_COLOR);
            } else if (index == 8) {
                this.mToExpandHintColorBgPressed = obtainStyledAttributes.getInteger(index, 1436129689);
            } else if (index == 12) {
                this.mToShrinkHintColorBgPressed = obtainStyledAttributes.getInteger(index, 1436129689);
            } else if (index == 4) {
                this.mCurrState = obtainStyledAttributes.getInteger(index, 0);
            } else if (index == 2) {
                this.mGapToExpandHint = obtainStyledAttributes.getString(index);
            } else if (index == 3) {
                this.mGapToShrinkHint = obtainStyledAttributes.getString(index);
            }
        }
        obtainStyledAttributes.recycle();
    }

    private String removeEndLineBreak(CharSequence charSequence) {
        String charSequence2 = charSequence.toString();
        while (charSequence2.endsWith("\n")) {
            charSequence2 = charSequence2.substring(0, charSequence2.length() - 1);
        }
        return charSequence2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setTextInternal(CharSequence charSequence, TextView.BufferType bufferType) {
        super.setText(charSequence, bufferType);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void toggle() {
        int i2 = this.mCurrState;
        if (i2 == 0) {
            this.mCurrState = 1;
            OnExpandListener onExpandListener = this.mOnExpandListener;
            if (onExpandListener != null) {
                onExpandListener.onExpand(this);
            }
        } else if (i2 == 1) {
            this.mCurrState = 0;
            OnExpandListener onExpandListener2 = this.mOnExpandListener;
            if (onExpandListener2 != null) {
                onExpandListener2.onShrink(this);
            }
        }
        setTextInternal(getNewTextByConfig(), this.mBufferType);
    }

    public int getExpandState() {
        return this.mCurrState;
    }

    public View.OnClickListener getOnClickListener(View view) {
        return getOnClickListenerV14(view);
    }

    public void setExpandListener(OnExpandListener onExpandListener) {
        this.mOnExpandListener = onExpandListener;
    }

    @Override // android.widget.TextView
    public void setText(CharSequence charSequence, TextView.BufferType bufferType) {
        this.mOrigText = charSequence;
        this.mBufferType = bufferType;
        setTextInternal(getNewTextByConfig(), bufferType);
    }

    public void updateForRecyclerView(CharSequence charSequence, int i2, int i3) {
        this.mFutureTextViewWidth = i2;
        this.mCurrState = i3;
        setText(charSequence);
    }

    public void updateForRecyclerView(CharSequence charSequence, TextView.BufferType bufferType, int i2) {
        this.mFutureTextViewWidth = i2;
        setText(charSequence, bufferType);
    }

    public void updateForRecyclerView(CharSequence charSequence, int i2) {
        this.mFutureTextViewWidth = i2;
        setText(charSequence);
    }

    public ExpandableTextView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mGapToExpandHint = " ";
        this.mGapToShrinkHint = " ";
        this.mToggleEnable = true;
        this.mShowToExpandHint = true;
        this.mShowToShrinkHint = true;
        this.mMaxLinesOnShrink = 2;
        this.mToExpandHintColor = TO_EXPAND_HINT_COLOR;
        this.mToShrinkHintColor = TO_SHRINK_HINT_COLOR;
        this.mToExpandHintColorBgPressed = 1436129689;
        this.mToShrinkHintColorBgPressed = 1436129689;
        this.mCurrState = 0;
        this.mBufferType = TextView.BufferType.NORMAL;
        this.mTextLineCount = -1;
        this.mLayoutWidth = 0;
        this.mFutureTextViewWidth = 0;
        initAttr(context, attributeSet);
        init();
    }

    public ExpandableTextView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.mGapToExpandHint = " ";
        this.mGapToShrinkHint = " ";
        this.mToggleEnable = true;
        this.mShowToExpandHint = true;
        this.mShowToShrinkHint = true;
        this.mMaxLinesOnShrink = 2;
        this.mToExpandHintColor = TO_EXPAND_HINT_COLOR;
        this.mToShrinkHintColor = TO_SHRINK_HINT_COLOR;
        this.mToExpandHintColorBgPressed = 1436129689;
        this.mToShrinkHintColorBgPressed = 1436129689;
        this.mCurrState = 0;
        this.mBufferType = TextView.BufferType.NORMAL;
        this.mTextLineCount = -1;
        this.mLayoutWidth = 0;
        this.mFutureTextViewWidth = 0;
        initAttr(context, attributeSet);
        init();
    }
}
