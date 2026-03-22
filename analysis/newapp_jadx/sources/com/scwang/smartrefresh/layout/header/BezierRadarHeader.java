package com.scwang.smartrefresh.layout.header;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.animation.AccelerateDecelerateInterpolator;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.core.view.ViewCompat;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import com.scwang.smartrefresh.layout.R$styleable;
import com.scwang.smartrefresh.layout.internal.InternalAbstract;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2897f;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p357c.C2904c;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;

/* loaded from: classes2.dex */
public class BezierRadarHeader extends InternalAbstract implements InterfaceC2897f {

    /* renamed from: A */
    public Animator f10693A;

    /* renamed from: B */
    public RectF f10694B;

    /* renamed from: g */
    public int f10695g;

    /* renamed from: h */
    public int f10696h;

    /* renamed from: i */
    public boolean f10697i;

    /* renamed from: j */
    public boolean f10698j;

    /* renamed from: k */
    public boolean f10699k;

    /* renamed from: l */
    public boolean f10700l;

    /* renamed from: m */
    public Path f10701m;

    /* renamed from: n */
    public Paint f10702n;

    /* renamed from: o */
    public int f10703o;

    /* renamed from: p */
    public int f10704p;

    /* renamed from: q */
    public int f10705q;

    /* renamed from: r */
    public int f10706r;

    /* renamed from: s */
    public float f10707s;

    /* renamed from: t */
    public float f10708t;

    /* renamed from: u */
    public float f10709u;

    /* renamed from: v */
    public float f10710v;

    /* renamed from: w */
    public int f10711w;

    /* renamed from: x */
    public float f10712x;

    /* renamed from: y */
    public float f10713y;

    /* renamed from: z */
    public float f10714z;

    /* renamed from: com.scwang.smartrefresh.layout.header.BezierRadarHeader$a */
    public class C4088a implements ValueAnimator.AnimatorUpdateListener {

        /* renamed from: c */
        public byte f10715c;

        public C4088a(byte b2) {
            this.f10715c = b2;
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            byte b2 = this.f10715c;
            if (b2 == 0) {
                BezierRadarHeader.this.f10714z = ((Float) valueAnimator.getAnimatedValue()).floatValue();
            } else if (1 == b2) {
                BezierRadarHeader bezierRadarHeader = BezierRadarHeader.this;
                if (bezierRadarHeader.f10699k) {
                    valueAnimator.cancel();
                    return;
                }
                bezierRadarHeader.f10704p = ((Integer) valueAnimator.getAnimatedValue()).intValue() / 2;
            } else if (2 == b2) {
                BezierRadarHeader.this.f10707s = ((Float) valueAnimator.getAnimatedValue()).floatValue();
            } else if (3 == b2) {
                BezierRadarHeader.this.f10710v = ((Float) valueAnimator.getAnimatedValue()).floatValue();
            } else if (4 == b2) {
                BezierRadarHeader.this.f10711w = ((Integer) valueAnimator.getAnimatedValue()).intValue();
            }
            BezierRadarHeader.this.invalidate();
        }
    }

    public BezierRadarHeader(Context context) {
        this(context, null);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: b */
    public void mo3350b(float f2, int i2, int i3) {
        this.f10705q = i2;
        invalidate();
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: c */
    public boolean mo3351c() {
        return this.f10700l;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: d */
    public void mo3352d(boolean z, float f2, int i2, int i3, int i4) {
        this.f10706r = i2;
        if (z || this.f10699k) {
            this.f10699k = true;
            this.f10703o = Math.min(i3, i2);
            this.f10704p = (int) (Math.max(0, i2 - i3) * 1.9f);
            this.f10708t = f2;
            invalidate();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void dispatchDraw(Canvas canvas) {
        int width = getWidth();
        int height = isInEditMode() ? getHeight() : this.f10706r;
        this.f10701m.reset();
        this.f10701m.lineTo(0.0f, this.f10703o);
        Path path = this.f10701m;
        int i2 = this.f10705q;
        float f2 = 2.0f;
        float f3 = i2 >= 0 ? i2 : width / 2.0f;
        float f4 = width;
        path.quadTo(f3, this.f10704p + r4, f4, this.f10703o);
        this.f10701m.lineTo(f4, 0.0f);
        this.f10702n.setColor(this.f10696h);
        canvas.drawPath(this.f10701m, this.f10702n);
        if (this.f10707s > 0.0f) {
            this.f10702n.setColor(this.f10695g);
            float m3387h = InterpolatorC2917b.m3387h(height);
            float f5 = 7.0f;
            float f6 = (f4 * 1.0f) / 7.0f;
            float f7 = this.f10708t;
            float f8 = (f6 * f7) - (f7 > 1.0f ? ((f7 - 1.0f) * f6) / f7 : 0.0f);
            float f9 = height;
            float f10 = f9 - (f7 > 1.0f ? (((f7 - 1.0f) * f9) / 2.0f) / f7 : 0.0f);
            int i3 = 0;
            while (i3 < 7) {
                float f11 = (i3 + 1.0f) - 4.0f;
                int i4 = i3;
                this.f10702n.setAlpha((int) ((1.0d - (1.0d / Math.pow((m3387h / 800.0d) + 1.0d, 15.0d))) * this.f10707s * (1.0f - ((Math.abs(f11) / f5) * f2)) * 255.0f));
                float f12 = (1.0f - (1.0f / ((m3387h / 10.0f) + 1.0f))) * this.f10709u;
                canvas.drawCircle((f11 * f8) + ((f4 / 2.0f) - (f12 / 2.0f)), f10 / 2.0f, f12, this.f10702n);
                i3 = i4 + 1;
                f5 = 7.0f;
                f2 = 2.0f;
            }
            this.f10702n.setAlpha(255);
        }
        if (this.f10693A != null || isInEditMode()) {
            float f13 = this.f10712x;
            float f14 = this.f10714z;
            float f15 = f13 * f14;
            float f16 = this.f10713y * f14;
            this.f10702n.setColor(this.f10695g);
            this.f10702n.setStyle(Paint.Style.FILL);
            float f17 = f4 / 2.0f;
            float f18 = height / 2.0f;
            canvas.drawCircle(f17, f18, f15, this.f10702n);
            this.f10702n.setStyle(Paint.Style.STROKE);
            float f19 = f16 + f15;
            canvas.drawCircle(f17, f18, f19, this.f10702n);
            this.f10702n.setColor((this.f10696h & ViewCompat.MEASURED_SIZE_MASK) | 1426063360);
            this.f10702n.setStyle(Paint.Style.FILL);
            this.f10694B.set(f17 - f15, f18 - f15, f17 + f15, f15 + f18);
            canvas.drawArc(this.f10694B, 270.0f, this.f10711w, true, this.f10702n);
            this.f10702n.setStyle(Paint.Style.STROKE);
            this.f10694B.set(f17 - f19, f18 - f19, f17 + f19, f18 + f19);
            canvas.drawArc(this.f10694B, 270.0f, this.f10711w, false, this.f10702n);
            this.f10702n.setStyle(Paint.Style.FILL);
        }
        if (this.f10710v > 0.0f) {
            this.f10702n.setColor(this.f10695g);
            canvas.drawCircle(f4 / 2.0f, height / 2.0f, this.f10710v, this.f10702n);
        }
        super.dispatchDraw(canvas);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p360f.InterfaceC2915f
    /* renamed from: e */
    public void mo3379e(@NonNull InterfaceC2900i interfaceC2900i, @NonNull EnumC2903b enumC2903b, @NonNull EnumC2903b enumC2903b2) {
        int ordinal = enumC2903b2.ordinal();
        if (ordinal == 0 || ordinal == 1) {
            this.f10707s = 1.0f;
            this.f10714z = 0.0f;
            this.f10710v = 0.0f;
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: j */
    public int mo3354j(@NonNull InterfaceC2900i interfaceC2900i, boolean z) {
        Animator animator = this.f10693A;
        if (animator != null) {
            animator.removeAllListeners();
            this.f10693A.end();
            this.f10693A = null;
        }
        int width = getWidth();
        int i2 = this.f10706r;
        ValueAnimator ofFloat = ValueAnimator.ofFloat(this.f10712x, (float) Math.sqrt((i2 * i2) + (width * width)));
        ofFloat.setDuration(400L);
        ofFloat.addUpdateListener(new C4088a((byte) 3));
        ofFloat.start();
        return 400;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: k */
    public void mo3355k(@NonNull InterfaceC2900i interfaceC2900i, int i2, int i3) {
        this.f10703o = i2 - 1;
        this.f10699k = false;
        float f2 = InterpolatorC2917b.f7984a;
        InterpolatorC2917b interpolatorC2917b = new InterpolatorC2917b(1);
        ValueAnimator ofFloat = ValueAnimator.ofFloat(1.0f, 0.0f);
        ofFloat.setInterpolator(interpolatorC2917b);
        ofFloat.addUpdateListener(new C4088a((byte) 2));
        ValueAnimator ofFloat2 = ValueAnimator.ofFloat(0.0f, 1.0f);
        ofFloat.setInterpolator(interpolatorC2917b);
        ofFloat2.addUpdateListener(new C4088a((byte) 0));
        ValueAnimator ofInt = ValueAnimator.ofInt(0, 360);
        ofInt.setDuration(720L);
        ofInt.setRepeatCount(-1);
        ofInt.setInterpolator(new AccelerateDecelerateInterpolator());
        ofInt.addUpdateListener(new C4088a((byte) 4));
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playSequentially(ofFloat, ofFloat2, ofInt);
        animatorSet.start();
        int i4 = this.f10704p;
        ValueAnimator ofInt2 = ValueAnimator.ofInt(i4, 0, -((int) (i4 * 0.8f)), 0, -((int) (i4 * 0.4f)), 0);
        ofInt2.addUpdateListener(new C4088a((byte) 1));
        ofInt2.setInterpolator(new InterpolatorC2917b(1));
        ofInt2.setDuration(800L);
        ofInt2.start();
        this.f10693A = animatorSet;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        Animator animator = this.f10693A;
        if (animator != null) {
            animator.removeAllListeners();
            this.f10693A.end();
            this.f10693A = null;
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    @Deprecated
    public void setPrimaryColors(@ColorInt int... iArr) {
        if (iArr.length > 0 && !this.f10697i) {
            this.f10696h = iArr[0];
            this.f10697i = true;
            this.f10697i = false;
        }
        if (iArr.length <= 1 || this.f10698j) {
            return;
        }
        this.f10695g = iArr[1];
        this.f10698j = true;
        this.f10698j = false;
    }

    public BezierRadarHeader(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        this.f10700l = false;
        this.f10705q = -1;
        this.f10706r = 0;
        this.f10711w = 0;
        this.f10712x = 0.0f;
        this.f10713y = 0.0f;
        this.f10714z = 0.0f;
        this.f10694B = new RectF(0.0f, 0.0f, 0.0f, 0.0f);
        this.f10744e = C2904c.f7955c;
        this.f10701m = new Path();
        Paint paint = new Paint();
        this.f10702n = paint;
        paint.setAntiAlias(true);
        this.f10709u = InterpolatorC2917b.m3382c(7.0f);
        this.f10712x = InterpolatorC2917b.m3382c(20.0f);
        this.f10713y = InterpolatorC2917b.m3382c(7.0f);
        this.f10702n.setStrokeWidth(InterpolatorC2917b.m3382c(3.0f));
        setMinimumHeight(InterpolatorC2917b.m3382c(100.0f));
        if (isInEditMode()) {
            this.f10703o = 1000;
            this.f10714z = 1.0f;
            this.f10711w = SubsamplingScaleImageView.ORIENTATION_270;
        } else {
            this.f10714z = 0.0f;
        }
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.BezierRadarHeader);
        this.f10700l = obtainStyledAttributes.getBoolean(R$styleable.BezierRadarHeader_srlEnableHorizontalDrag, this.f10700l);
        int i2 = R$styleable.BezierRadarHeader_srlAccentColor;
        this.f10695g = obtainStyledAttributes.getColor(i2, -1);
        this.f10698j = true;
        int i3 = R$styleable.BezierRadarHeader_srlPrimaryColor;
        this.f10696h = obtainStyledAttributes.getColor(i3, -14540254);
        this.f10697i = true;
        this.f10698j = obtainStyledAttributes.hasValue(i2);
        this.f10697i = obtainStyledAttributes.hasValue(i3);
        obtainStyledAttributes.recycle();
    }
}
