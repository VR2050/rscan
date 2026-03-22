package com.google.android.exoplayer2.p395ui;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import androidx.annotation.Nullable;

/* loaded from: classes.dex */
public final class AspectRatioFrameLayout extends FrameLayout {

    /* renamed from: c */
    public final RunnableC3315c f9569c;

    /* renamed from: e */
    @Nullable
    public InterfaceC3314b f9570e;

    /* renamed from: f */
    public float f9571f;

    /* renamed from: g */
    public int f9572g;

    /* renamed from: com.google.android.exoplayer2.ui.AspectRatioFrameLayout$b */
    public interface InterfaceC3314b {
        /* renamed from: a */
        void m4079a(float f2, float f3, boolean z);
    }

    /* renamed from: com.google.android.exoplayer2.ui.AspectRatioFrameLayout$c */
    public final class RunnableC3315c implements Runnable {

        /* renamed from: c */
        public float f9573c;

        /* renamed from: e */
        public float f9574e;

        /* renamed from: f */
        public boolean f9575f;

        /* renamed from: g */
        public boolean f9576g;

        public RunnableC3315c(C3313a c3313a) {
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f9576g = false;
            InterfaceC3314b interfaceC3314b = AspectRatioFrameLayout.this.f9570e;
            if (interfaceC3314b == null) {
                return;
            }
            interfaceC3314b.m4079a(this.f9573c, this.f9574e, this.f9575f);
        }
    }

    public AspectRatioFrameLayout(Context context) {
        this(context, null);
    }

    public int getResizeMode() {
        return this.f9572g;
    }

    @Override // android.widget.FrameLayout, android.view.View
    public void onMeasure(int i2, int i3) {
        float f2;
        float f3;
        super.onMeasure(i2, i3);
        if (this.f9571f <= 0.0f) {
            return;
        }
        int measuredWidth = getMeasuredWidth();
        int measuredHeight = getMeasuredHeight();
        float f4 = measuredWidth;
        float f5 = measuredHeight;
        float f6 = f4 / f5;
        float f7 = (this.f9571f / f6) - 1.0f;
        if (Math.abs(f7) <= 0.01f) {
            RunnableC3315c runnableC3315c = this.f9569c;
            runnableC3315c.f9573c = this.f9571f;
            runnableC3315c.f9574e = f6;
            runnableC3315c.f9575f = false;
            if (runnableC3315c.f9576g) {
                return;
            }
            runnableC3315c.f9576g = true;
            AspectRatioFrameLayout.this.post(runnableC3315c);
            return;
        }
        int i4 = this.f9572g;
        if (i4 != 0) {
            if (i4 != 1) {
                if (i4 == 2) {
                    f2 = this.f9571f;
                } else if (i4 == 4) {
                    if (f7 > 0.0f) {
                        f2 = this.f9571f;
                    } else {
                        f3 = this.f9571f;
                    }
                }
                measuredWidth = (int) (f5 * f2);
            } else {
                f3 = this.f9571f;
            }
            measuredHeight = (int) (f4 / f3);
        } else if (f7 > 0.0f) {
            f3 = this.f9571f;
            measuredHeight = (int) (f4 / f3);
        } else {
            f2 = this.f9571f;
            measuredWidth = (int) (f5 * f2);
        }
        RunnableC3315c runnableC3315c2 = this.f9569c;
        runnableC3315c2.f9573c = this.f9571f;
        runnableC3315c2.f9574e = f6;
        runnableC3315c2.f9575f = true;
        if (!runnableC3315c2.f9576g) {
            runnableC3315c2.f9576g = true;
            AspectRatioFrameLayout.this.post(runnableC3315c2);
        }
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(measuredWidth, 1073741824), View.MeasureSpec.makeMeasureSpec(measuredHeight, 1073741824));
    }

    public void setAspectRatio(float f2) {
        if (this.f9571f != f2) {
            this.f9571f = f2;
            requestLayout();
        }
    }

    public void setAspectRatioListener(@Nullable InterfaceC3314b interfaceC3314b) {
        this.f9570e = interfaceC3314b;
    }

    public void setResizeMode(int i2) {
        if (this.f9572g != i2) {
            this.f9572g = i2;
            requestLayout();
        }
    }

    public AspectRatioFrameLayout(Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f9572g = 0;
        if (attributeSet != null) {
            TypedArray obtainStyledAttributes = context.getTheme().obtainStyledAttributes(attributeSet, R$styleable.AspectRatioFrameLayout, 0, 0);
            try {
                this.f9572g = obtainStyledAttributes.getInt(R$styleable.AspectRatioFrameLayout_resize_mode, 0);
            } finally {
                obtainStyledAttributes.recycle();
            }
        }
        this.f9569c = new RunnableC3315c(null);
    }
}
