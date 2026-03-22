package com.jbzd.media.movecartoons.view.text;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.CountDownTimer;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.AnimationUtils;
import android.widget.TextSwitcher;
import android.widget.TextView;
import android.widget.ViewSwitcher;
import androidx.core.view.ViewCompat;
import com.jbzd.media.movecartoons.R$styleable;

/* loaded from: classes2.dex */
public class ScrollPageTextSwitcher extends TextSwitcher implements ViewSwitcher.ViewFactory {
    private final long DEFAULT_TIME_SWITCH_INTERVAL;
    private Context mContext;
    private int mCurrentIndex;
    private String[] mData;
    private long mTimeInterval;
    private CountDownTimer timer;
    private int txtColor;
    private float txtSize;

    public ScrollPageTextSwitcher(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.DEFAULT_TIME_SWITCH_INTERVAL = 1000L;
        this.mTimeInterval = 1000L;
        this.mCurrentIndex = 0;
        this.txtSize = 12.0f;
        this.txtColor = ViewCompat.MEASURED_STATE_MASK;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ScrollPageTextSwitcher);
        this.txtSize = obtainStyledAttributes.getDimension(1, 12.0f);
        this.txtColor = obtainStyledAttributes.getColor(0, ViewCompat.MEASURED_STATE_MASK);
        obtainStyledAttributes.recycle();
        this.mContext = context;
        setFactory(this);
    }

    public static /* synthetic */ int access$008(ScrollPageTextSwitcher scrollPageTextSwitcher) {
        int i2 = scrollPageTextSwitcher.mCurrentIndex;
        scrollPageTextSwitcher.mCurrentIndex = i2 + 1;
        return i2;
    }

    public ScrollPageTextSwitcher bindData(String[] strArr) {
        this.mData = strArr;
        return this;
    }

    public void cancel() {
        CountDownTimer countDownTimer = this.timer;
        if (countDownTimer != null) {
            countDownTimer.cancel();
            this.timer = null;
        }
    }

    @Override // android.widget.ViewSwitcher.ViewFactory
    public View makeView() {
        TextView textView = new TextView(this.mContext);
        textView.getPaint().setTextSize(this.txtSize);
        textView.setTextColor(this.txtColor);
        return textView;
    }

    public ScrollPageTextSwitcher setInAnimation(int i2) {
        setInAnimation(AnimationUtils.loadAnimation(this.mContext, i2));
        return this;
    }

    public ScrollPageTextSwitcher setOutAnimation(int i2) {
        setOutAnimation(AnimationUtils.loadAnimation(this.mContext, i2));
        return this;
    }

    public void startSwitch(long j2) {
        cancel();
        this.mTimeInterval = j2;
        String[] strArr = this.mData;
        if (strArr == null || strArr.length == 0 || this.timer != null) {
            return;
        }
        CountDownTimer countDownTimer = new CountDownTimer(2147483647L, j2) { // from class: com.jbzd.media.movecartoons.view.text.ScrollPageTextSwitcher.1
            @Override // android.os.CountDownTimer
            public void onFinish() {
            }

            @Override // android.os.CountDownTimer
            public void onTick(long j3) {
                int length = ScrollPageTextSwitcher.this.mCurrentIndex % ScrollPageTextSwitcher.this.mData.length;
                ScrollPageTextSwitcher.access$008(ScrollPageTextSwitcher.this);
                ScrollPageTextSwitcher scrollPageTextSwitcher = ScrollPageTextSwitcher.this;
                scrollPageTextSwitcher.setText(scrollPageTextSwitcher.mData[length]);
            }
        };
        this.timer = countDownTimer;
        countDownTimer.start();
    }
}
