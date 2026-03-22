package com.qunidayede.supportlibrary.widget.marquee;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.widget.ViewFlipper;
import androidx.core.content.res.ResourcesCompat;
import androidx.core.view.ViewCompat;
import com.qunidayede.supportlibrary.R$styleable;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class MarqueeView<T> extends ViewFlipper {

    /* renamed from: c */
    public int f10384c;

    /* renamed from: e */
    public int f10385e;

    /* renamed from: f */
    public int f10386f;

    /* renamed from: g */
    public int f10387g;

    /* renamed from: h */
    public int f10388h;

    /* renamed from: i */
    public List<T> f10389i;

    /* renamed from: com.qunidayede.supportlibrary.widget.marquee.MarqueeView$a */
    public interface InterfaceC4058a {
    }

    public MarqueeView(Context context) {
        this(context, null);
    }

    public List<T> getMessages() {
        return this.f10389i;
    }

    public int getPosition() {
        return ((Integer) getCurrentView().getTag()).intValue();
    }

    public void setMessages(List<T> list) {
        this.f10389i = list;
    }

    public void setOnItemClickListener(InterfaceC4058a interfaceC4058a) {
    }

    public void setTypeface(Typeface typeface) {
    }

    public MarqueeView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f10384c = 3000;
        this.f10385e = 1000;
        this.f10386f = 14;
        this.f10387g = ViewCompat.MEASURED_STATE_MASK;
        this.f10388h = 0;
        this.f10389i = new ArrayList();
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.MarqueeViewStyle, 0, 0);
        this.f10384c = obtainStyledAttributes.getInteger(R$styleable.MarqueeViewStyle_mvInterval, this.f10384c);
        int i2 = R$styleable.MarqueeViewStyle_mvAnimDuration;
        obtainStyledAttributes.hasValue(i2);
        this.f10385e = obtainStyledAttributes.getInteger(i2, this.f10385e);
        obtainStyledAttributes.getBoolean(R$styleable.MarqueeViewStyle_mvSingleLine, false);
        int i3 = R$styleable.MarqueeViewStyle_mvTextSize;
        if (obtainStyledAttributes.hasValue(i3)) {
            int dimension = (int) obtainStyledAttributes.getDimension(i3, this.f10386f);
            this.f10386f = dimension;
            this.f10386f = (int) ((dimension / context.getResources().getDisplayMetrics().scaledDensity) + 0.5f);
        }
        this.f10387g = obtainStyledAttributes.getColor(R$styleable.MarqueeViewStyle_mvTextColor, this.f10387g);
        int resourceId = obtainStyledAttributes.getResourceId(R$styleable.MarqueeViewStyle_mvFont, 0);
        if (resourceId != 0) {
            ResourcesCompat.getFont(context, resourceId);
        }
        obtainStyledAttributes.getInt(R$styleable.MarqueeViewStyle_mvGravity, 0);
        int i4 = R$styleable.MarqueeViewStyle_mvDirection;
        if (obtainStyledAttributes.hasValue(i4)) {
            this.f10388h = obtainStyledAttributes.getInt(i4, this.f10388h);
        }
        obtainStyledAttributes.recycle();
        setFlipInterval(this.f10384c);
    }
}
