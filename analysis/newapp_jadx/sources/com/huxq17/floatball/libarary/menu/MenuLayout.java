package com.huxq17.floatball.libarary.menu;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import java.util.Objects;
import p005b.p299p.p300a.p301a.p302a.InterfaceC2716a;
import p005b.p299p.p300a.p301a.p302a.RunnableC2717b;

/* loaded from: classes2.dex */
public class MenuLayout extends ViewGroup implements InterfaceC2716a {

    /* renamed from: c */
    public static int f9876c;

    /* renamed from: e */
    public int f9877e;

    /* renamed from: f */
    public int f9878f;

    /* renamed from: g */
    public float f9879g;

    /* renamed from: h */
    public float f9880h;

    /* renamed from: i */
    public int f9881i;

    /* renamed from: j */
    public boolean f9882j;

    /* renamed from: k */
    public boolean f9883k;

    /* renamed from: l */
    public int f9884l;

    /* renamed from: m */
    public int f9885m;

    /* renamed from: n */
    public int f9886n;

    /* renamed from: o */
    public RunnableC2717b f9887o;

    public MenuLayout(Context context) {
        this(context, null);
    }

    /* renamed from: d */
    public static int m4180d(float f2, int i2, int i3, int i4, int i5) {
        if (i2 < 2) {
            return i5;
        }
        if (f2 != 360.0f) {
            i2--;
        }
        return Math.max((int) (((i3 + i4) / 2) / Math.sin(Math.toRadians((f2 / i2) / 2.0f))), i5);
    }

    private int getLayoutSize() {
        int m4180d = m4180d(Math.abs(this.f9880h - this.f9879g), getChildCount(), this.f9877e, this.f9878f, f9876c);
        this.f9881i = m4180d;
        return (m4180d * 2) + this.f9877e + this.f9878f + 20;
    }

    private int getRadiusAndPadding() {
        return (this.f9878f * 2) + this.f9881i;
    }

    @Override // p005b.p299p.p300a.p301a.p302a.InterfaceC2716a
    /* renamed from: a */
    public void mo3237a() {
        this.f9883k = false;
        if (this.f9882j) {
            return;
        }
        Objects.requireNonNull((FloatMenu) getParent());
        throw null;
    }

    @Override // p005b.p299p.p300a.p301a.p302a.InterfaceC2716a
    /* renamed from: b */
    public void mo3238b(int i2, int i3, int i4, int i5) {
        m4182e(i4);
    }

    /* renamed from: c */
    public void m4181c(int i2) {
        int layoutSize = getLayoutSize();
        switch (i2) {
            case 1:
                int i3 = layoutSize / 2;
                this.f9885m = i3 - getRadiusAndPadding();
                this.f9886n = i3 - getRadiusAndPadding();
                break;
            case 2:
                int i4 = layoutSize / 2;
                this.f9885m = i4;
                this.f9886n = i4 - getRadiusAndPadding();
                break;
            case 3:
                int i5 = layoutSize / 2;
                this.f9885m = getRadiusAndPadding() + i5;
                this.f9886n = i5 - getRadiusAndPadding();
                break;
            case 4:
                int i6 = layoutSize / 2;
                this.f9885m = i6 - getRadiusAndPadding();
                this.f9886n = i6;
                break;
            case 5:
                int i7 = layoutSize / 2;
                this.f9885m = i7;
                this.f9886n = i7;
                break;
            case 6:
                int i8 = layoutSize / 2;
                this.f9885m = getRadiusAndPadding() + i8;
                this.f9886n = i8;
                break;
            case 7:
                int i9 = layoutSize / 2;
                this.f9885m = i9 - getRadiusAndPadding();
                this.f9886n = i9 + getRadiusAndPadding();
                break;
            case 8:
                int i10 = layoutSize / 2;
                this.f9885m = i10;
                this.f9886n = i10 + getRadiusAndPadding();
                break;
            case 9:
                int i11 = layoutSize / 2;
                this.f9885m = getRadiusAndPadding() + i11;
                this.f9886n = i11 + getRadiusAndPadding();
                break;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x001f, code lost:
    
        if (r3 == 90.0f) goto L8;
     */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0031 A[LOOP:0: B:5:0x002f->B:6:0x0031, LOOP_END] */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m4182e(int r20) {
        /*
            r19 = this;
            r0 = r19
            int r1 = r19.getChildCount()
            float r2 = r0.f9879g
            float r3 = r0.f9880h
            float r3 = r3 - r2
            float r3 = java.lang.Math.abs(r3)
            r4 = 2
            r5 = 1
            if (r1 != r5) goto L19
        L13:
            int r5 = r1 + 1
            float r5 = (float) r5
            float r3 = r3 / r5
            float r2 = r2 + r3
            goto L2e
        L19:
            if (r1 != r4) goto L26
            r5 = 1119092736(0x42b40000, float:90.0)
            int r5 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r5 != 0) goto L13
        L21:
            int r5 = r1 + (-1)
            float r5 = (float) r5
        L24:
            float r3 = r3 / r5
            goto L2e
        L26:
            r5 = 1135869952(0x43b40000, float:360.0)
            int r5 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r5 != 0) goto L21
            float r5 = (float) r1
            goto L24
        L2e:
            r5 = 0
        L2f:
            if (r5 >= r1) goto L80
            int r6 = r0.getChildDrawingOrder(r1, r5)
            int r7 = r0.f9885m
            int r8 = r0.f9886n
            int r9 = r0.f9877e
            double r10 = (double) r7
            r7 = r20
            double r12 = (double) r7
            double r14 = (double) r2
            double r16 = java.lang.Math.toRadians(r14)
            double r16 = java.lang.Math.cos(r16)
            double r16 = r16 * r12
            double r16 = r16 + r10
            double r10 = (double) r8
            double r14 = java.lang.Math.toRadians(r14)
            double r14 = java.lang.Math.sin(r14)
            double r14 = r14 * r12
            double r14 = r14 + r10
            android.graphics.Rect r8 = new android.graphics.Rect
            int r9 = r9 / r4
            double r9 = (double) r9
            double r11 = r16 - r9
            int r11 = (int) r11
            double r12 = r14 - r9
            int r12 = (int) r12
            r18 = r5
            double r4 = r16 + r9
            int r4 = (int) r4
            double r14 = r14 + r9
            int r5 = (int) r14
            r8.<init>(r11, r12, r4, r5)
            float r2 = r2 + r3
            android.view.View r4 = r0.getChildAt(r6)
            int r5 = r8.left
            int r6 = r8.top
            int r9 = r8.right
            int r8 = r8.bottom
            r4.layout(r5, r6, r9, r8)
            int r5 = r18 + 1
            r4 = 2
            goto L2f
        L80:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.huxq17.floatball.libarary.menu.MenuLayout.m4182e(int):void");
    }

    @Override // android.view.ViewGroup
    public int getChildDrawingOrder(int i2, int i3) {
        int i4 = (int) (this.f9879g / 90.0f);
        return !(i4 == 0 || i4 == 3) ? (i2 - i3) - 1 : i3;
    }

    public int getChildSize() {
        return this.f9877e;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        if (this.f9883k) {
            return;
        }
        m4181c(this.f9884l);
        m4182e(0);
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        int layoutSize = getLayoutSize();
        setMeasuredDimension(layoutSize, layoutSize);
        int childCount = getChildCount();
        for (int i4 = 0; i4 < childCount; i4++) {
            getChildAt(i4).measure(View.MeasureSpec.makeMeasureSpec(this.f9877e, 1073741824), View.MeasureSpec.makeMeasureSpec(this.f9877e, 1073741824));
        }
    }

    @Override // android.view.View, android.view.ViewParent
    public void requestLayout() {
        if (this.f9883k) {
            return;
        }
        super.requestLayout();
    }

    public void setChildSize(int i2) {
        this.f9877e = i2;
    }

    public void setExpand(boolean z) {
        this.f9882j = z;
    }

    public MenuLayout(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f9878f = 5;
        this.f9882j = false;
        this.f9883k = false;
        this.f9884l = 1;
        this.f9885m = 0;
        this.f9886n = 0;
        float f2 = context.getResources().getDisplayMetrics().scaledDensity;
        if (f2 <= 1.0f) {
            f2 = 1.0f;
        } else if (f2 <= 1.5d) {
            f2 = 1.5f;
        } else if (f2 <= 2.0f) {
            f2 = 2.0f;
        } else if (f2 <= 3.0f) {
            f2 = 3.0f;
        }
        f9876c = (int) ((65.0f * f2) + 0.5f);
        this.f9887o = new RunnableC2717b(this);
        setChildrenDrawingOrderEnabled(true);
    }
}
