package com.scwang.smartrefresh.layout.footer;

import android.animation.TimeInterpolator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.animation.AccelerateDecelerateInterpolator;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.graphics.ColorUtils;
import com.scwang.smartrefresh.layout.R$styleable;
import com.scwang.smartrefresh.layout.internal.InternalAbstract;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2896e;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p357c.C2904c;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;

/* loaded from: classes2.dex */
public class BallPulseFooter extends InternalAbstract implements InterfaceC2896e {

    /* renamed from: g */
    public boolean f10675g;

    /* renamed from: h */
    public boolean f10676h;

    /* renamed from: i */
    public Paint f10677i;

    /* renamed from: j */
    public int f10678j;

    /* renamed from: k */
    public int f10679k;

    /* renamed from: l */
    public float f10680l;

    /* renamed from: m */
    public long f10681m;

    /* renamed from: n */
    public boolean f10682n;

    /* renamed from: o */
    public TimeInterpolator f10683o;

    public BallPulseFooter(Context context) {
        this(context, null);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void dispatchDraw(Canvas canvas) {
        int width = getWidth();
        int height = getHeight();
        float min = Math.min(width, height);
        float f2 = this.f10680l;
        float f3 = (min - (f2 * 2.0f)) / 6.0f;
        float f4 = f3 * 2.0f;
        float f5 = (width / 2.0f) - (f2 + f4);
        float f6 = height / 2.0f;
        long currentTimeMillis = System.currentTimeMillis();
        int i2 = 0;
        while (i2 < 3) {
            int i3 = i2 + 1;
            float interpolation = this.f10683o.getInterpolation((currentTimeMillis - this.f10681m) - (i3 * 120) > 0 ? (r10 % 750) / 750.0f : 0.0f);
            canvas.save();
            float f7 = i2;
            canvas.translate((this.f10680l * f7) + (f4 * f7) + f5, f6);
            if (interpolation < 0.5d) {
                float f8 = 1.0f - ((interpolation * 2.0f) * 0.7f);
                canvas.scale(f8, f8);
            } else {
                float f9 = ((interpolation * 2.0f) * 0.7f) - 0.4f;
                canvas.scale(f9, f9);
            }
            canvas.drawCircle(0.0f, 0.0f, f3, this.f10677i);
            canvas.restore();
            i2 = i3;
        }
        super.dispatchDraw(canvas);
        if (this.f10682n) {
            invalidate();
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: f */
    public void mo3353f(@NonNull InterfaceC2900i interfaceC2900i, int i2, int i3) {
        if (this.f10682n) {
            return;
        }
        invalidate();
        this.f10682n = true;
        this.f10681m = System.currentTimeMillis();
        this.f10677i.setColor(this.f10679k);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: j */
    public int mo3354j(@NonNull InterfaceC2900i interfaceC2900i, boolean z) {
        this.f10682n = false;
        this.f10681m = 0L;
        this.f10677i.setColor(this.f10678j);
        return 0;
    }

    /* renamed from: r */
    public BallPulseFooter m4628r(@ColorInt int i2) {
        this.f10678j = i2;
        this.f10675g = true;
        if (!this.f10682n) {
            this.f10677i.setColor(i2);
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    @Deprecated
    public void setPrimaryColors(@ColorInt int... iArr) {
        if (!this.f10676h && iArr.length > 1) {
            int i2 = iArr[0];
            this.f10679k = i2;
            this.f10676h = true;
            if (this.f10682n) {
                this.f10677i.setColor(i2);
            }
            this.f10676h = false;
        }
        if (this.f10675g) {
            return;
        }
        if (iArr.length > 1) {
            m4628r(iArr[1]);
        } else if (iArr.length > 0) {
            m4628r(ColorUtils.compositeColors(-1711276033, iArr[0]));
        }
        this.f10675g = false;
    }

    public BallPulseFooter(Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        this.f10678j = -1118482;
        this.f10679k = -1615546;
        this.f10681m = 0L;
        this.f10682n = false;
        this.f10683o = new AccelerateDecelerateInterpolator();
        setMinimumHeight(InterpolatorC2917b.m3382c(60.0f));
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.BallPulseFooter);
        Paint paint = new Paint();
        this.f10677i = paint;
        paint.setColor(-1);
        this.f10677i.setStyle(Paint.Style.FILL);
        this.f10677i.setAntiAlias(true);
        this.f10744e = C2904c.f7953a;
        this.f10744e = C2904c.f7958f[obtainStyledAttributes.getInt(R$styleable.BallPulseFooter_srlClassicsSpinnerStyle, 0)];
        int i2 = R$styleable.BallPulseFooter_srlNormalColor;
        if (obtainStyledAttributes.hasValue(i2)) {
            m4628r(obtainStyledAttributes.getColor(i2, 0));
        }
        int i3 = R$styleable.BallPulseFooter_srlAnimatingColor;
        if (obtainStyledAttributes.hasValue(i3)) {
            int color = obtainStyledAttributes.getColor(i3, 0);
            this.f10679k = color;
            this.f10676h = true;
            if (this.f10682n) {
                this.f10677i.setColor(color);
            }
        }
        obtainStyledAttributes.recycle();
        this.f10680l = InterpolatorC2917b.m3382c(4.0f);
    }
}
