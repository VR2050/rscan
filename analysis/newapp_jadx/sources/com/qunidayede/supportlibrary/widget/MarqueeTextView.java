package com.qunidayede.supportlibrary.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.os.Handler;
import android.os.Looper;
import android.text.TextPaint;
import android.util.AttributeSet;
import android.view.animation.LinearInterpolator;
import android.widget.Scroller;
import androidx.appcompat.widget.AppCompatTextView;
import com.qunidayede.supportlibrary.R$styleable;

/* loaded from: classes2.dex */
public class MarqueeTextView extends AppCompatTextView {

    /* renamed from: c */
    public Scroller f10374c;

    /* renamed from: e */
    public int f10375e;

    /* renamed from: f */
    public int f10376f;

    /* renamed from: g */
    public boolean f10377g;

    /* renamed from: h */
    public boolean f10378h;

    /* renamed from: i */
    public int f10379i;

    /* renamed from: j */
    public int f10380j;

    /* renamed from: com.qunidayede.supportlibrary.widget.MarqueeTextView$a */
    public class RunnableC4057a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ int f10381c;

        /* renamed from: e */
        public final /* synthetic */ int f10382e;

        public RunnableC4057a(int i2, int i3) {
            this.f10381c = i2;
            this.f10382e = i3;
        }

        @Override // java.lang.Runnable
        public void run() {
            MarqueeTextView marqueeTextView = MarqueeTextView.this;
            marqueeTextView.f10374c.startScroll(marqueeTextView.f10376f, 0, this.f10381c, 0, this.f10382e);
            MarqueeTextView.this.invalidate();
            MarqueeTextView.this.f10377g = false;
        }
    }

    public MarqueeTextView(Context context) {
        this(context, null);
    }

    /* renamed from: a */
    public final void m4581a(Context context, AttributeSet attributeSet) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.MarqueeTextView);
        this.f10375e = obtainStyledAttributes.getInt(R$styleable.MarqueeTextView_scroll_interval, 10000);
        this.f10379i = obtainStyledAttributes.getInt(R$styleable.MarqueeTextView_scroll_mode, 100);
        this.f10380j = obtainStyledAttributes.getInt(R$styleable.MarqueeTextView_scroll_first_delay, 1000);
        obtainStyledAttributes.recycle();
        setSingleLine();
        setEllipsize(null);
    }

    /* renamed from: b */
    public void m4582b() {
        if (this.f10377g) {
            setHorizontallyScrolling(true);
            if (this.f10374c == null) {
                Scroller scroller = new Scroller(getContext(), new LinearInterpolator());
                this.f10374c = scroller;
                setScroller(scroller);
            }
            TextPaint paint = getPaint();
            Rect rect = new Rect();
            String charSequence = getText().toString();
            paint.getTextBounds(charSequence, 0, charSequence.length(), rect);
            int width = rect.width();
            int i2 = width - this.f10376f;
            int intValue = Double.valueOf(((this.f10375e * i2) * 1.0d) / width).intValue();
            if (this.f10378h) {
                new Handler(Looper.getMainLooper()).postDelayed(new RunnableC4057a(i2, intValue), this.f10380j);
                return;
            }
            this.f10374c.startScroll(this.f10376f, 0, i2, 0, intValue);
            invalidate();
            this.f10377g = false;
        }
    }

    /* renamed from: c */
    public void m4583c() {
        this.f10376f = 0;
        this.f10377g = true;
        this.f10378h = true;
        m4582b();
    }

    @Override // android.widget.TextView, android.view.View
    public void computeScroll() {
        super.computeScroll();
        Scroller scroller = this.f10374c;
        if (scroller == null || !scroller.isFinished() || this.f10377g) {
            return;
        }
        if (this.f10379i != 101) {
            this.f10377g = true;
            this.f10376f = getWidth() * (-1);
            this.f10378h = false;
            m4582b();
            return;
        }
        Scroller scroller2 = this.f10374c;
        if (scroller2 == null) {
            return;
        }
        this.f10377g = true;
        scroller2.startScroll(0, 0, 0, 0, 0);
    }

    public int getRndDuration() {
        return this.f10375e;
    }

    public int getScrollFirstDelay() {
        return this.f10380j;
    }

    public int getScrollMode() {
        return this.f10379i;
    }

    public void setRndDuration(int i2) {
        this.f10375e = i2;
    }

    public void setScrollFirstDelay(int i2) {
        this.f10380j = i2;
    }

    public void setScrollMode(int i2) {
        this.f10379i = i2;
    }

    public MarqueeTextView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public MarqueeTextView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f10376f = 0;
        this.f10377g = true;
        this.f10378h = true;
        m4581a(context, attributeSet);
    }
}
