package com.king.zxing;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Paint;
import android.graphics.Rect;
import android.text.TextPaint;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.View;
import androidx.annotation.ColorInt;
import androidx.annotation.ColorRes;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import java.util.ArrayList;
import java.util.List;
import p005b.p085c.p088b.p089a.C1345b;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p266d.C2536r;

/* loaded from: classes2.dex */
public final class ViewfinderView extends View {

    /* renamed from: A */
    public int f10158A;

    /* renamed from: B */
    public int f10159B;

    /* renamed from: C */
    public int f10160C;

    /* renamed from: D */
    public int f10161D;

    /* renamed from: E */
    public int f10162E;

    /* renamed from: F */
    public int f10163F;

    /* renamed from: G */
    public float f10164G;

    /* renamed from: H */
    public List<C2536r> f10165H;

    /* renamed from: I */
    public List<C2536r> f10166I;

    /* renamed from: c */
    public Paint f10167c;

    /* renamed from: e */
    public TextPaint f10168e;

    /* renamed from: f */
    public int f10169f;

    /* renamed from: g */
    public int f10170g;

    /* renamed from: h */
    public int f10171h;

    /* renamed from: i */
    public int f10172i;

    /* renamed from: j */
    public int f10173j;

    /* renamed from: k */
    public float f10174k;

    /* renamed from: l */
    public int f10175l;

    /* renamed from: m */
    public String f10176m;

    /* renamed from: n */
    public int f10177n;

    /* renamed from: o */
    public float f10178o;

    /* renamed from: p */
    public int f10179p;

    /* renamed from: q */
    public int f10180q;

    /* renamed from: r */
    public boolean f10181r;

    /* renamed from: s */
    public int f10182s;

    /* renamed from: t */
    public int f10183t;

    /* renamed from: u */
    public int f10184u;

    /* renamed from: v */
    public int f10185v;

    /* renamed from: w */
    public EnumC3921a f10186w;

    /* renamed from: x */
    public int f10187x;

    /* renamed from: y */
    public int f10188y;

    /* renamed from: z */
    public Rect f10189z;

    /* renamed from: com.king.zxing.ViewfinderView$a */
    public enum EnumC3921a {
        NONE(0),
        LINE(1),
        GRID(2);


        /* renamed from: h */
        public int f10194h;

        EnumC3921a(int i2) {
            this.f10194h = i2;
        }
    }

    public ViewfinderView(Context context) {
        this(context, null);
    }

    private DisplayMetrics getDisplayMetrics() {
        return getResources().getDisplayMetrics();
    }

    /* renamed from: a */
    public int m4521a(int i2) {
        String hexString = Integer.toHexString(i2);
        StringBuilder m586H = C1499a.m586H("01");
        m586H.append(hexString.substring(2));
        return Integer.valueOf(m586H.toString(), 16).intValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x00ec A[LOOP:0: B:20:0x00e8->B:22:0x00ec, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0120 A[LOOP:1: B:29:0x0119->B:31:0x0120, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0138 A[EDGE_INSN: B:32:0x0138->B:33:0x0138 BREAK  A[LOOP:1: B:29:0x0119->B:31:0x0120], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x013e  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0144  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onDraw(android.graphics.Canvas r21) {
        /*
            Method dump skipped, instructions count: 986
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.king.zxing.ViewfinderView.onDraw(android.graphics.Canvas):void");
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        int paddingLeft = (getPaddingLeft() + ((this.f10182s - this.f10184u) / 2)) - getPaddingRight();
        int paddingTop = (getPaddingTop() + ((this.f10183t - this.f10185v) / 2)) - getPaddingBottom();
        this.f10189z = new Rect(paddingLeft, paddingTop, this.f10184u + paddingLeft, this.f10185v + paddingTop);
    }

    public void setLabelText(String str) {
        this.f10176m = str;
    }

    public void setLabelTextColor(@ColorInt int i2) {
        this.f10177n = i2;
    }

    public void setLabelTextColorResource(@ColorRes int i2) {
        this.f10177n = ContextCompat.getColor(getContext(), i2);
    }

    public void setLabelTextSize(float f2) {
        this.f10178o = f2;
    }

    public void setLaserStyle(EnumC3921a enumC3921a) {
        this.f10186w = enumC3921a;
    }

    public void setShowResultPoint(boolean z) {
        this.f10181r = z;
    }

    public ViewfinderView(Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ViewfinderView(Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        int i3;
        EnumC3921a enumC3921a;
        int i4 = 0;
        this.f10179p = 0;
        this.f10180q = 0;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ViewfinderView);
        this.f10169f = obtainStyledAttributes.getColor(R$styleable.ViewfinderView_maskColor, ContextCompat.getColor(context, R$color.viewfinder_mask));
        this.f10170g = obtainStyledAttributes.getColor(R$styleable.ViewfinderView_frameColor, ContextCompat.getColor(context, R$color.viewfinder_frame));
        this.f10172i = obtainStyledAttributes.getColor(R$styleable.ViewfinderView_cornerColor, ContextCompat.getColor(context, R$color.viewfinder_corner));
        this.f10171h = obtainStyledAttributes.getColor(R$styleable.ViewfinderView_laserColor, ContextCompat.getColor(context, R$color.viewfinder_laser));
        this.f10173j = obtainStyledAttributes.getColor(R$styleable.ViewfinderView_resultPointColor, ContextCompat.getColor(context, R$color.viewfinder_result_point_color));
        this.f10176m = obtainStyledAttributes.getString(R$styleable.ViewfinderView_labelText);
        this.f10177n = obtainStyledAttributes.getColor(R$styleable.ViewfinderView_labelTextColor, ContextCompat.getColor(context, R$color.viewfinder_text_color));
        this.f10178o = obtainStyledAttributes.getDimension(R$styleable.ViewfinderView_labelTextSize, TypedValue.applyDimension(2, 14.0f, getResources().getDisplayMetrics()));
        this.f10174k = obtainStyledAttributes.getDimension(R$styleable.ViewfinderView_labelTextPadding, TypedValue.applyDimension(1, 24.0f, getResources().getDisplayMetrics()));
        int i5 = obtainStyledAttributes.getInt(R$styleable.ViewfinderView_labelTextLocation, 0);
        int[] com$king$zxing$ViewfinderView$TextLocation$s$values = C1345b.com$king$zxing$ViewfinderView$TextLocation$s$values();
        int i6 = 0;
        while (true) {
            if (i6 >= 2) {
                i3 = 1;
                break;
            }
            i3 = com$king$zxing$ViewfinderView$TextLocation$s$values[i6];
            if (C1345b.m350b(i3) == i5) {
                break;
            } else {
                i6++;
            }
        }
        this.f10175l = i3;
        this.f10181r = obtainStyledAttributes.getBoolean(R$styleable.ViewfinderView_showResultPoint, false);
        this.f10184u = obtainStyledAttributes.getDimensionPixelSize(R$styleable.ViewfinderView_frameWidth, 0);
        this.f10185v = obtainStyledAttributes.getDimensionPixelSize(R$styleable.ViewfinderView_frameHeight, 0);
        int i7 = obtainStyledAttributes.getInt(R$styleable.ViewfinderView_laserStyle, 1);
        EnumC3921a[] values = EnumC3921a.values();
        while (true) {
            if (i4 < 3) {
                enumC3921a = values[i4];
                if (enumC3921a.f10194h == i7) {
                    break;
                } else {
                    i4++;
                }
            } else {
                enumC3921a = EnumC3921a.LINE;
                break;
            }
        }
        this.f10186w = enumC3921a;
        this.f10187x = obtainStyledAttributes.getInt(R$styleable.ViewfinderView_gridColumn, 20);
        this.f10188y = (int) obtainStyledAttributes.getDimension(R$styleable.ViewfinderView_gridHeight, TypedValue.applyDimension(1, 40.0f, getResources().getDisplayMetrics()));
        this.f10158A = (int) obtainStyledAttributes.getDimension(R$styleable.ViewfinderView_cornerRectWidth, TypedValue.applyDimension(1, 4.0f, getResources().getDisplayMetrics()));
        this.f10159B = (int) obtainStyledAttributes.getDimension(R$styleable.ViewfinderView_cornerRectHeight, TypedValue.applyDimension(1, 16.0f, getResources().getDisplayMetrics()));
        this.f10160C = (int) obtainStyledAttributes.getDimension(R$styleable.ViewfinderView_scannerLineMoveDistance, TypedValue.applyDimension(1, 2.0f, getResources().getDisplayMetrics()));
        this.f10161D = (int) obtainStyledAttributes.getDimension(R$styleable.ViewfinderView_scannerLineHeight, TypedValue.applyDimension(1, 5.0f, getResources().getDisplayMetrics()));
        this.f10162E = (int) obtainStyledAttributes.getDimension(R$styleable.ViewfinderView_frameLineWidth, TypedValue.applyDimension(1, 1.0f, getResources().getDisplayMetrics()));
        this.f10163F = obtainStyledAttributes.getInteger(R$styleable.ViewfinderView_scannerAnimationDelay, 15);
        this.f10164G = obtainStyledAttributes.getFloat(R$styleable.ViewfinderView_frameRatio, 0.625f);
        obtainStyledAttributes.recycle();
        this.f10167c = new Paint(1);
        this.f10168e = new TextPaint(1);
        this.f10165H = new ArrayList(5);
        this.f10166I = null;
        this.f10182s = getDisplayMetrics().widthPixels;
        this.f10183t = getDisplayMetrics().heightPixels;
        int min = (int) (Math.min(this.f10182s, r7) * this.f10164G);
        int i8 = this.f10184u;
        if (i8 <= 0 || i8 > this.f10182s) {
            this.f10184u = min;
        }
        int i9 = this.f10185v;
        if (i9 <= 0 || i9 > this.f10183t) {
            this.f10185v = min;
        }
    }
}
