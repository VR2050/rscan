package com.flyco.tablayout.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.util.AttributeSet;
import android.view.View;
import androidx.appcompat.widget.AppCompatTextView;
import com.flyco.tablayout.R$styleable;

/* loaded from: classes.dex */
public class MsgView extends AppCompatTextView {

    /* renamed from: c */
    public Context f9180c;

    /* renamed from: e */
    public GradientDrawable f9181e;

    /* renamed from: f */
    public int f9182f;

    /* renamed from: g */
    public int f9183g;

    /* renamed from: h */
    public int f9184h;

    /* renamed from: i */
    public int f9185i;

    /* renamed from: j */
    public boolean f9186j;

    /* renamed from: k */
    public boolean f9187k;

    public MsgView(Context context) {
        this(context, null);
    }

    /* renamed from: a */
    public int m4015a(float f2) {
        return (int) ((f2 * this.f9180c.getResources().getDisplayMetrics().density) + 0.5f);
    }

    /* renamed from: b */
    public void m4016b() {
        StateListDrawable stateListDrawable = new StateListDrawable();
        GradientDrawable gradientDrawable = this.f9181e;
        int i2 = this.f9182f;
        int i3 = this.f9185i;
        gradientDrawable.setColor(i2);
        gradientDrawable.setCornerRadius(this.f9183g);
        gradientDrawable.setStroke(this.f9184h, i3);
        stateListDrawable.addState(new int[]{-16842919}, this.f9181e);
        setBackground(stateListDrawable);
    }

    public int getBackgroundColor() {
        return this.f9182f;
    }

    public int getCornerRadius() {
        return this.f9183g;
    }

    public int getStrokeColor() {
        return this.f9185i;
    }

    public int getStrokeWidth() {
        return this.f9184h;
    }

    @Override // androidx.appcompat.widget.AppCompatTextView, android.widget.TextView, android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        super.onLayout(z, i2, i3, i4, i5);
        if (this.f9186j) {
            setCornerRadius(getHeight() / 2);
        } else {
            m4016b();
        }
    }

    @Override // androidx.appcompat.widget.AppCompatTextView, android.widget.TextView, android.view.View
    public void onMeasure(int i2, int i3) {
        if (!this.f9187k || getWidth() <= 0 || getHeight() <= 0) {
            super.onMeasure(i2, i3);
        } else {
            int makeMeasureSpec = View.MeasureSpec.makeMeasureSpec(Math.max(getWidth(), getHeight()), 1073741824);
            super.onMeasure(makeMeasureSpec, makeMeasureSpec);
        }
    }

    @Override // android.view.View
    public void setBackgroundColor(int i2) {
        this.f9182f = i2;
        m4016b();
    }

    public void setCornerRadius(int i2) {
        this.f9183g = m4015a(i2);
        m4016b();
    }

    public void setIsRadiusHalfHeight(boolean z) {
        this.f9186j = z;
        m4016b();
    }

    public void setIsWidthHeightEqual(boolean z) {
        this.f9187k = z;
        m4016b();
    }

    public void setStrokeColor(int i2) {
        this.f9185i = i2;
        m4016b();
    }

    public void setStrokeWidth(int i2) {
        this.f9184h = m4015a(i2);
        m4016b();
    }

    public MsgView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public MsgView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f9181e = new GradientDrawable();
        this.f9180c = context;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.MsgView);
        this.f9182f = obtainStyledAttributes.getColor(R$styleable.MsgView_mv_backgroundColor, 0);
        this.f9183g = obtainStyledAttributes.getDimensionPixelSize(R$styleable.MsgView_mv_cornerRadius, 0);
        this.f9184h = obtainStyledAttributes.getDimensionPixelSize(R$styleable.MsgView_mv_strokeWidth, 0);
        this.f9185i = obtainStyledAttributes.getColor(R$styleable.MsgView_mv_strokeColor, 0);
        this.f9186j = obtainStyledAttributes.getBoolean(R$styleable.MsgView_mv_isRadiusHalfHeight, false);
        this.f9187k = obtainStyledAttributes.getBoolean(R$styleable.MsgView_mv_isWidthHeightEqual, false);
        obtainStyledAttributes.recycle();
    }
}
