package com.scwang.smart.refresh.header;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.core.view.ViewCompat;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.scwang.smart.refresh.header.material.CircleImageView;
import com.scwang.smart.refresh.header.material.R$styleable;
import com.scwang.smart.refresh.layout.SmartRefreshLayout;
import com.scwang.smart.refresh.layout.simple.SimpleComponent;
import p005b.p340x.p341a.p343b.p345b.p346a.C2870c;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2874d;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2875e;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f;
import p005b.p340x.p341a.p343b.p347c.p349b.C2879c;
import p005b.p340x.p341a.p343b.p347c.p349b.EnumC2878b;
import p005b.p340x.p341a.p343b.p347c.p352e.InterpolatorC2889b;

/* loaded from: classes2.dex */
public class MaterialHeader extends SimpleComponent implements InterfaceC2874d {

    /* renamed from: g */
    public boolean f10490g;

    /* renamed from: h */
    public int f10491h;

    /* renamed from: i */
    public ImageView f10492i;

    /* renamed from: j */
    public C2870c f10493j;

    /* renamed from: k */
    public int f10494k;

    /* renamed from: l */
    public int f10495l;

    /* renamed from: m */
    public Path f10496m;

    /* renamed from: n */
    public Paint f10497n;

    /* renamed from: o */
    public EnumC2878b f10498o;

    /* renamed from: p */
    public boolean f10499p;

    /* renamed from: q */
    public boolean f10500q;

    public MaterialHeader(Context context) {
        this(context, null);
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: d */
    public void mo3316d(boolean z, float f2, int i2, int i3, int i4) {
        EnumC2878b enumC2878b = this.f10498o;
        EnumC2878b enumC2878b2 = EnumC2878b.Refreshing;
        if (enumC2878b == enumC2878b2) {
            return;
        }
        if (this.f10499p) {
            this.f10495l = Math.min(i2, i3);
            this.f10494k = Math.max(0, i2 - i3);
            postInvalidate();
        }
        if (z || !(this.f10493j.isRunning() || this.f10490g)) {
            if (this.f10498o != enumC2878b2) {
                float f3 = i3;
                float max = (((float) Math.max(Math.min(1.0f, Math.abs((i2 * 1.0f) / f3)) - 0.4d, ShadowDrawableWrapper.COS_45)) * 5.0f) / 3.0f;
                double max2 = Math.max(0.0f, Math.min(Math.abs(i2) - i3, f3 * 2.0f) / f3) / 4.0f;
                float pow = ((float) (max2 - Math.pow(max2, 2.0d))) * 2.0f;
                this.f10493j.m3311d(true);
                this.f10493j.m3310c(0.0f, Math.min(0.8f, max * 0.8f));
                C2870c c2870c = this.f10493j;
                float min = Math.min(1.0f, max);
                C2870c.a aVar = c2870c.f7819h;
                if (aVar.f7842p != min) {
                    aVar.f7842p = min;
                    c2870c.invalidateSelf();
                }
                this.f10493j.m3308a(((pow * 2.0f) + ((max * 0.4f) - 0.25f)) * 0.5f);
            }
            ImageView imageView = this.f10492i;
            float f4 = i2;
            imageView.setTranslationY(Math.min(f4, (this.f10491h / 2.0f) + (f4 / 2.0f)));
            imageView.setAlpha(Math.min(1.0f, (f4 * 4.0f) / this.f10491h));
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void dispatchDraw(Canvas canvas) {
        if (this.f10499p) {
            this.f10496m.reset();
            this.f10496m.lineTo(0.0f, this.f10495l);
            this.f10496m.quadTo(getMeasuredWidth() / 2.0f, (this.f10494k * 1.9f) + this.f10495l, getMeasuredWidth(), this.f10495l);
            this.f10496m.lineTo(getMeasuredWidth(), 0.0f);
            canvas.drawPath(this.f10496m, this.f10497n);
        }
        super.dispatchDraw(canvas);
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: e */
    public void mo3317e(@NonNull InterfaceC2876f interfaceC2876f, int i2, int i3) {
        this.f10493j.start();
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: f */
    public int mo3318f(@NonNull InterfaceC2876f interfaceC2876f, boolean z) {
        ImageView imageView = this.f10492i;
        this.f10493j.stop();
        imageView.animate().scaleX(0.0f).scaleY(0.0f);
        this.f10490g = true;
        return 0;
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: g */
    public void mo3319g(@NonNull InterfaceC2875e interfaceC2875e, int i2, int i3) {
        if (!this.f10499p) {
            SmartRefreshLayout.C4074k c4074k = (SmartRefreshLayout.C4074k) interfaceC2875e;
            if (equals(SmartRefreshLayout.this.f10509B0)) {
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (!smartRefreshLayout.f10553g0) {
                    smartRefreshLayout.f10553g0 = true;
                    smartRefreshLayout.f10530M = false;
                }
            } else if (equals(SmartRefreshLayout.this.f10511C0)) {
                SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                if (!smartRefreshLayout2.f10555h0) {
                    smartRefreshLayout2.f10555h0 = true;
                    smartRefreshLayout2.f10532N = false;
                }
            }
        }
        if (isInEditMode()) {
            int i4 = i2 / 2;
            this.f10495l = i4;
            this.f10494k = i4;
        }
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2885f
    /* renamed from: h */
    public void mo3328h(@NonNull InterfaceC2876f interfaceC2876f, @NonNull EnumC2878b enumC2878b, @NonNull EnumC2878b enumC2878b2) {
        ImageView imageView = this.f10492i;
        this.f10498o = enumC2878b2;
        if (enumC2878b2.ordinal() != 1) {
            return;
        }
        this.f10490g = false;
        imageView.setVisibility(0);
        imageView.setTranslationY(0.0f);
        imageView.setScaleX(1.0f);
        imageView.setScaleY(1.0f);
    }

    @Override // android.widget.RelativeLayout, android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        int i6;
        if (getChildCount() == 0) {
            return;
        }
        ImageView imageView = this.f10492i;
        int measuredWidth = getMeasuredWidth();
        int measuredWidth2 = imageView.getMeasuredWidth();
        int measuredHeight = imageView.getMeasuredHeight();
        if (!isInEditMode() || (i6 = this.f10495l) <= 0) {
            int i7 = measuredWidth / 2;
            int i8 = measuredWidth2 / 2;
            imageView.layout(i7 - i8, -measuredHeight, i7 + i8, 0);
            return;
        }
        int i9 = i6 - (measuredHeight / 2);
        int i10 = measuredWidth / 2;
        int i11 = measuredWidth2 / 2;
        imageView.layout(i10 - i11, i9, i10 + i11, measuredHeight + i9);
        this.f10493j.m3311d(true);
        this.f10493j.m3310c(0.0f, 0.8f);
        C2870c c2870c = this.f10493j;
        C2870c.a aVar = c2870c.f7819h;
        if (aVar.f7842p != 1.0f) {
            aVar.f7842p = 1.0f;
            c2870c.invalidateSelf();
        }
        imageView.setAlpha(1.0f);
        imageView.setVisibility(0);
    }

    @Override // android.widget.RelativeLayout, android.view.View
    public void onMeasure(int i2, int i3) {
        super.setMeasuredDimension(View.MeasureSpec.getSize(i2), View.MeasureSpec.getSize(i3));
        this.f10492i.measure(View.MeasureSpec.makeMeasureSpec(this.f10491h, 1073741824), View.MeasureSpec.makeMeasureSpec(this.f10491h, 1073741824));
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    @Deprecated
    public void setPrimaryColors(@ColorInt int... iArr) {
        if (iArr.length > 0) {
            this.f10497n.setColor(iArr[0]);
        }
    }

    public MaterialHeader(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        this.f10499p = false;
        this.f10500q = true;
        this.f10627e = C2879c.f7891e;
        setMinimumHeight(InterpolatorC2889b.m3333c(100.0f));
        C2870c c2870c = new C2870c(this);
        this.f10493j = c2870c;
        C2870c.a aVar = c2870c.f7819h;
        aVar.f7835i = new int[]{-16737844, -48060, -10053376, -5609780, -30720};
        aVar.m3313a(0);
        CircleImageView circleImageView = new CircleImageView(context, -328966);
        this.f10492i = circleImageView;
        circleImageView.setImageDrawable(this.f10493j);
        this.f10492i.setAlpha(0.0f);
        addView(this.f10492i);
        this.f10491h = (int) (getResources().getDisplayMetrics().density * 40.0f);
        this.f10496m = new Path();
        Paint paint = new Paint();
        this.f10497n = paint;
        paint.setAntiAlias(true);
        this.f10497n.setStyle(Paint.Style.FILL);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.MaterialHeader);
        this.f10499p = obtainStyledAttributes.getBoolean(R$styleable.MaterialHeader_srlShowBezierWave, this.f10499p);
        this.f10500q = obtainStyledAttributes.getBoolean(R$styleable.MaterialHeader_srlScrollableWhenRefreshing, this.f10500q);
        this.f10497n.setColor(obtainStyledAttributes.getColor(R$styleable.MaterialHeader_srlPrimaryColor, -15614977));
        int i2 = R$styleable.MaterialHeader_srlShadowRadius;
        if (obtainStyledAttributes.hasValue(i2)) {
            this.f10497n.setShadowLayer(obtainStyledAttributes.getDimensionPixelOffset(i2, 0), 0.0f, 0.0f, obtainStyledAttributes.getColor(R$styleable.MaterialHeader_mhShadowColor, ViewCompat.MEASURED_STATE_MASK));
            setLayerType(1, null);
        }
        this.f10499p = obtainStyledAttributes.getBoolean(R$styleable.MaterialHeader_mhShowBezierWave, this.f10499p);
        this.f10500q = obtainStyledAttributes.getBoolean(R$styleable.MaterialHeader_mhScrollableWhenRefreshing, this.f10500q);
        int i3 = R$styleable.MaterialHeader_mhPrimaryColor;
        if (obtainStyledAttributes.hasValue(i3)) {
            this.f10497n.setColor(obtainStyledAttributes.getColor(i3, -15614977));
        }
        int i4 = R$styleable.MaterialHeader_mhShadowRadius;
        if (obtainStyledAttributes.hasValue(i4)) {
            this.f10497n.setShadowLayer(obtainStyledAttributes.getDimensionPixelOffset(i4, 0), 0.0f, 0.0f, obtainStyledAttributes.getColor(R$styleable.MaterialHeader_mhShadowColor, ViewCompat.MEASURED_STATE_MASK));
            setLayerType(1, null);
        }
        obtainStyledAttributes.recycle();
    }
}
