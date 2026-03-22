package com.qunidayede.supportlibrary.widget.switchbutton;

import android.animation.Animator;
import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Checkable;
import androidx.core.view.ViewCompat;
import com.qunidayede.supportlibrary.R$styleable;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

/* loaded from: classes2.dex */
public class SwitchButton extends View implements Checkable {

    /* renamed from: c */
    public static final int f10396c = m4585c(48.0f);

    /* renamed from: e */
    public static final int f10397e = m4585c(32.0f);

    /* renamed from: A */
    public float f10398A;

    /* renamed from: B */
    public float f10399B;

    /* renamed from: C */
    public float f10400C;

    /* renamed from: D */
    public int f10401D;

    /* renamed from: E */
    public int f10402E;

    /* renamed from: F */
    public float f10403F;

    /* renamed from: G */
    public float f10404G;

    /* renamed from: H */
    public Paint f10405H;

    /* renamed from: I */
    public Paint f10406I;

    /* renamed from: J */
    public C4063e f10407J;

    /* renamed from: K */
    public C4063e f10408K;

    /* renamed from: L */
    public C4063e f10409L;

    /* renamed from: M */
    public RectF f10410M;

    /* renamed from: N */
    public int f10411N;

    /* renamed from: O */
    public ValueAnimator f10412O;

    /* renamed from: P */
    public final ArgbEvaluator f10413P;

    /* renamed from: Q */
    public boolean f10414Q;

    /* renamed from: R */
    public boolean f10415R;

    /* renamed from: S */
    public boolean f10416S;

    /* renamed from: T */
    public boolean f10417T;

    /* renamed from: U */
    public boolean f10418U;

    /* renamed from: V */
    public boolean f10419V;

    /* renamed from: W */
    public boolean f10420W;

    /* renamed from: a0 */
    public boolean f10421a0;

    /* renamed from: b0 */
    public InterfaceC4062d f10422b0;

    /* renamed from: c0 */
    public long f10423c0;

    /* renamed from: d0 */
    public Runnable f10424d0;

    /* renamed from: e0 */
    public ValueAnimator.AnimatorUpdateListener f10425e0;

    /* renamed from: f */
    public int f10426f;

    /* renamed from: f0 */
    public Animator.AnimatorListener f10427f0;

    /* renamed from: g */
    public int f10428g;

    /* renamed from: h */
    public int f10429h;

    /* renamed from: i */
    public float f10430i;

    /* renamed from: j */
    public float f10431j;

    /* renamed from: k */
    public float f10432k;

    /* renamed from: l */
    public float f10433l;

    /* renamed from: m */
    public float f10434m;

    /* renamed from: n */
    public float f10435n;

    /* renamed from: o */
    public float f10436o;

    /* renamed from: p */
    public float f10437p;

    /* renamed from: q */
    public int f10438q;

    /* renamed from: r */
    public int f10439r;

    /* renamed from: s */
    public int f10440s;

    /* renamed from: t */
    public int f10441t;

    /* renamed from: u */
    public int f10442u;

    /* renamed from: v */
    public int f10443v;

    /* renamed from: w */
    public float f10444w;

    /* renamed from: x */
    public int f10445x;

    /* renamed from: y */
    public int f10446y;

    /* renamed from: z */
    public float f10447z;

    /* renamed from: com.qunidayede.supportlibrary.widget.switchbutton.SwitchButton$a */
    public class RunnableC4059a implements Runnable {
        public RunnableC4059a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            SwitchButton switchButton = SwitchButton.this;
            int i2 = switchButton.f10411N;
            if (i2 != 0) {
                return;
            }
            if (!(i2 != 0) && switchButton.f10419V) {
                if (switchButton.f10412O.isRunning()) {
                    switchButton.f10412O.cancel();
                }
                switchButton.f10411N = 1;
                C4063e.m4597a(switchButton.f10408K, switchButton.f10407J);
                C4063e.m4597a(switchButton.f10409L, switchButton.f10407J);
                if (switchButton.isChecked()) {
                    C4063e c4063e = switchButton.f10409L;
                    int i3 = switchButton.f10440s;
                    c4063e.f10452b = i3;
                    c4063e.f10451a = switchButton.f10404G;
                    c4063e.f10453c = i3;
                } else {
                    C4063e c4063e2 = switchButton.f10409L;
                    c4063e2.f10452b = switchButton.f10439r;
                    c4063e2.f10451a = switchButton.f10403F;
                    c4063e2.f10454d = switchButton.f10430i;
                }
                switchButton.f10412O.start();
            }
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.widget.switchbutton.SwitchButton$b */
    public class C4060b implements ValueAnimator.AnimatorUpdateListener {
        public C4060b() {
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            float floatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
            SwitchButton switchButton = SwitchButton.this;
            int i2 = switchButton.f10411N;
            if (i2 == 1 || i2 == 3 || i2 == 4) {
                switchButton.f10407J.f10453c = ((Integer) switchButton.f10413P.evaluate(floatValue, Integer.valueOf(switchButton.f10408K.f10453c), Integer.valueOf(SwitchButton.this.f10409L.f10453c))).intValue();
                SwitchButton switchButton2 = SwitchButton.this;
                C4063e c4063e = switchButton2.f10407J;
                C4063e c4063e2 = switchButton2.f10408K;
                float f2 = c4063e2.f10454d;
                C4063e c4063e3 = switchButton2.f10409L;
                c4063e.f10454d = C1499a.m627m(c4063e3.f10454d, f2, floatValue, f2);
                if (switchButton2.f10411N != 1) {
                    float f3 = c4063e2.f10451a;
                    c4063e.f10451a = C1499a.m627m(c4063e3.f10451a, f3, floatValue, f3);
                }
                c4063e.f10452b = ((Integer) switchButton2.f10413P.evaluate(floatValue, Integer.valueOf(c4063e2.f10452b), Integer.valueOf(SwitchButton.this.f10409L.f10452b))).intValue();
            } else if (i2 == 5) {
                C4063e c4063e4 = switchButton.f10407J;
                float f4 = switchButton.f10408K.f10451a;
                float m627m = C1499a.m627m(switchButton.f10409L.f10451a, f4, floatValue, f4);
                c4063e4.f10451a = m627m;
                float f5 = switchButton.f10403F;
                float f6 = (m627m - f5) / (switchButton.f10404G - f5);
                c4063e4.f10452b = ((Integer) switchButton.f10413P.evaluate(f6, Integer.valueOf(switchButton.f10439r), Integer.valueOf(SwitchButton.this.f10440s))).intValue();
                SwitchButton switchButton3 = SwitchButton.this;
                C4063e c4063e5 = switchButton3.f10407J;
                c4063e5.f10454d = switchButton3.f10430i * f6;
                c4063e5.f10453c = ((Integer) switchButton3.f10413P.evaluate(f6, 0, Integer.valueOf(SwitchButton.this.f10442u))).intValue();
            }
            SwitchButton.this.postInvalidate();
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.widget.switchbutton.SwitchButton$c */
    public class C4061c implements Animator.AnimatorListener {
        public C4061c() {
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animator) {
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            SwitchButton switchButton = SwitchButton.this;
            int i2 = switchButton.f10411N;
            if (i2 == 1) {
                switchButton.f10411N = 2;
                C4063e c4063e = switchButton.f10407J;
                c4063e.f10453c = 0;
                c4063e.f10454d = switchButton.f10430i;
                switchButton.postInvalidate();
                return;
            }
            if (i2 == 3) {
                switchButton.f10411N = 0;
                switchButton.postInvalidate();
                return;
            }
            if (i2 == 4) {
                switchButton.f10411N = 0;
                switchButton.postInvalidate();
                SwitchButton.this.m4589a();
            } else {
                if (i2 != 5) {
                    return;
                }
                switchButton.f10414Q = !switchButton.f10414Q;
                switchButton.f10411N = 0;
                switchButton.postInvalidate();
                SwitchButton.this.m4589a();
            }
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationRepeat(Animator animator) {
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationStart(Animator animator) {
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.widget.switchbutton.SwitchButton$d */
    public interface InterfaceC4062d {
        /* renamed from: a */
        void m4596a(SwitchButton switchButton, boolean z);
    }

    /* renamed from: com.qunidayede.supportlibrary.widget.switchbutton.SwitchButton$e */
    public static class C4063e {

        /* renamed from: a */
        public float f10451a;

        /* renamed from: b */
        public int f10452b;

        /* renamed from: c */
        public int f10453c;

        /* renamed from: d */
        public float f10454d;

        /* renamed from: a */
        public static void m4597a(C4063e c4063e, C4063e c4063e2) {
            Objects.requireNonNull(c4063e);
            c4063e.f10451a = c4063e2.f10451a;
            c4063e.f10452b = c4063e2.f10452b;
            c4063e.f10453c = c4063e2.f10453c;
            c4063e.f10454d = c4063e2.f10454d;
        }
    }

    public SwitchButton(Context context) {
        super(context);
        this.f10410M = new RectF();
        this.f10411N = 0;
        this.f10413P = new ArgbEvaluator();
        this.f10419V = false;
        this.f10420W = false;
        this.f10421a0 = false;
        this.f10424d0 = new RunnableC4059a();
        this.f10425e0 = new C4060b();
        this.f10427f0 = new C4061c();
        m4591e(context, null);
    }

    /* renamed from: b */
    public static float m4584b(float f2) {
        return TypedValue.applyDimension(1, f2, Resources.getSystem().getDisplayMetrics());
    }

    /* renamed from: c */
    public static int m4585c(float f2) {
        return (int) m4584b(f2);
    }

    /* renamed from: h */
    public static boolean m4586h(TypedArray typedArray, int i2, boolean z) {
        return typedArray == null ? z : typedArray.getBoolean(i2, z);
    }

    /* renamed from: i */
    public static int m4587i(TypedArray typedArray, int i2, int i3) {
        return typedArray == null ? i3 : typedArray.getColor(i2, i3);
    }

    /* renamed from: j */
    public static int m4588j(TypedArray typedArray, int i2, int i3) {
        return typedArray == null ? i3 : typedArray.getDimensionPixelOffset(i2, i3);
    }

    private void setCheckedViewState(C4063e c4063e) {
        c4063e.f10454d = this.f10430i;
        c4063e.f10452b = this.f10440s;
        c4063e.f10453c = this.f10442u;
        c4063e.f10451a = this.f10404G;
        this.f10405H.setColor(this.f10402E);
    }

    private void setUncheckViewState(C4063e c4063e) {
        c4063e.f10454d = 0.0f;
        c4063e.f10452b = this.f10439r;
        c4063e.f10453c = 0;
        c4063e.f10451a = this.f10403F;
        this.f10405H.setColor(this.f10401D);
    }

    /* renamed from: a */
    public final void m4589a() {
        InterfaceC4062d interfaceC4062d = this.f10422b0;
        if (interfaceC4062d != null) {
            this.f10421a0 = true;
            interfaceC4062d.m4596a(this, isChecked());
        }
        this.f10421a0 = false;
    }

    /* renamed from: d */
    public final void m4590d(Canvas canvas, float f2, float f3, float f4, float f5, float f6, Paint paint) {
        canvas.drawRoundRect(f2, f3, f4, f5, f6, f6, paint);
    }

    /* renamed from: e */
    public final void m4591e(Context context, AttributeSet attributeSet) {
        TypedArray obtainStyledAttributes = attributeSet != null ? context.obtainStyledAttributes(attributeSet, R$styleable.SwitchButton) : null;
        this.f10417T = m4586h(obtainStyledAttributes, R$styleable.SwitchButton_sb_shadow_effect, true);
        this.f10445x = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_uncheckcircle_color, -5592406);
        this.f10446y = m4588j(obtainStyledAttributes, R$styleable.SwitchButton_sb_uncheckcircle_width, m4585c(1.5f));
        this.f10447z = m4584b(10.0f);
        int i2 = R$styleable.SwitchButton_sb_uncheckcircle_radius;
        float m4584b = m4584b(4.0f);
        if (obtainStyledAttributes != null) {
            m4584b = obtainStyledAttributes.getDimension(i2, m4584b);
        }
        this.f10398A = m4584b;
        this.f10399B = m4584b(4.0f);
        this.f10400C = m4584b(4.0f);
        this.f10426f = m4588j(obtainStyledAttributes, R$styleable.SwitchButton_sb_shadow_radius, m4585c(2.5f));
        this.f10428g = m4588j(obtainStyledAttributes, R$styleable.SwitchButton_sb_shadow_offset, m4585c(1.5f));
        this.f10429h = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_shadow_color, 855638016);
        this.f10439r = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_uncheck_color, -2236963);
        this.f10440s = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_checked_color, -11414681);
        this.f10441t = m4588j(obtainStyledAttributes, R$styleable.SwitchButton_sb_border_width, m4585c(1.0f));
        this.f10442u = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_checkline_color, -1);
        this.f10443v = m4588j(obtainStyledAttributes, R$styleable.SwitchButton_sb_checkline_width, m4585c(1.0f));
        this.f10444w = m4584b(6.0f);
        int m4587i = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_button_color, -1);
        this.f10401D = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_uncheckbutton_color, m4587i);
        this.f10402E = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_checkedbutton_color, m4587i);
        int i3 = R$styleable.SwitchButton_sb_effect_duration;
        int i4 = IjkMediaCodecInfo.RANK_SECURE;
        if (obtainStyledAttributes != null) {
            i4 = obtainStyledAttributes.getInt(i3, IjkMediaCodecInfo.RANK_SECURE);
        }
        this.f10414Q = m4586h(obtainStyledAttributes, R$styleable.SwitchButton_sb_checked, false);
        this.f10415R = m4586h(obtainStyledAttributes, R$styleable.SwitchButton_sb_text, false);
        this.f10418U = m4586h(obtainStyledAttributes, R$styleable.SwitchButton_sb_show_indicator, true);
        this.f10438q = m4587i(obtainStyledAttributes, R$styleable.SwitchButton_sb_background, -1);
        this.f10416S = m4586h(obtainStyledAttributes, R$styleable.SwitchButton_sb_enable_effect, true);
        if (obtainStyledAttributes != null) {
            obtainStyledAttributes.recycle();
        }
        this.f10406I = new Paint(1);
        Paint paint = new Paint(1);
        this.f10405H = paint;
        paint.setColor(m4587i);
        if (this.f10417T) {
            this.f10405H.setShadowLayer(this.f10426f, 0.0f, this.f10428g, this.f10429h);
        }
        this.f10407J = new C4063e();
        this.f10408K = new C4063e();
        this.f10409L = new C4063e();
        ValueAnimator ofFloat = ValueAnimator.ofFloat(0.0f, 1.0f);
        this.f10412O = ofFloat;
        ofFloat.setDuration(i4);
        this.f10412O.setRepeatCount(0);
        this.f10412O.addUpdateListener(this.f10425e0);
        this.f10412O.addListener(this.f10427f0);
        super.setClickable(true);
        setPadding(0, 0, 0, 0);
        setLayerType(1, null);
    }

    /* renamed from: f */
    public final boolean m4592f() {
        return this.f10411N == 2;
    }

    /* renamed from: g */
    public final boolean m4593g() {
        int i2 = this.f10411N;
        return i2 == 1 || i2 == 3;
    }

    @Override // android.widget.Checkable
    public boolean isChecked() {
        return this.f10414Q;
    }

    /* renamed from: k */
    public final void m4594k() {
        if (m4592f() || m4593g()) {
            if (this.f10412O.isRunning()) {
                this.f10412O.cancel();
            }
            this.f10411N = 3;
            C4063e.m4597a(this.f10408K, this.f10407J);
            if (isChecked()) {
                setCheckedViewState(this.f10409L);
            } else {
                setUncheckViewState(this.f10409L);
            }
            this.f10412O.start();
        }
    }

    /* renamed from: l */
    public final void m4595l(boolean z, boolean z2) {
        if (isEnabled()) {
            if (this.f10421a0) {
                throw new RuntimeException("should NOT switch the state in method: [onCheckedChanged]!");
            }
            if (!this.f10420W) {
                this.f10414Q = !this.f10414Q;
                if (z2) {
                    m4589a();
                    return;
                }
                return;
            }
            if (this.f10412O.isRunning()) {
                this.f10412O.cancel();
            }
            if (this.f10416S && z) {
                this.f10411N = 5;
                C4063e.m4597a(this.f10408K, this.f10407J);
                if (isChecked()) {
                    setUncheckViewState(this.f10409L);
                } else {
                    setCheckedViewState(this.f10409L);
                }
                this.f10412O.start();
                return;
            }
            this.f10414Q = !this.f10414Q;
            if (isChecked()) {
                setCheckedViewState(this.f10407J);
            } else {
                setUncheckViewState(this.f10407J);
            }
            postInvalidate();
            if (z2) {
                m4589a();
            }
        }
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        this.f10406I.setStrokeWidth(this.f10441t);
        this.f10406I.setStyle(Paint.Style.FILL);
        this.f10406I.setColor(this.f10438q);
        m4590d(canvas, this.f10433l, this.f10434m, this.f10435n, this.f10436o, this.f10430i, this.f10406I);
        this.f10406I.setStyle(Paint.Style.STROKE);
        this.f10406I.setColor(this.f10439r);
        m4590d(canvas, this.f10433l, this.f10434m, this.f10435n, this.f10436o, this.f10430i, this.f10406I);
        if (this.f10418U) {
            int i2 = this.f10445x;
            float f2 = this.f10446y;
            float f3 = this.f10435n - this.f10447z;
            float f4 = this.f10437p;
            float f5 = this.f10398A;
            Paint paint = this.f10406I;
            paint.setStyle(Paint.Style.STROKE);
            paint.setColor(i2);
            paint.setStrokeWidth(f2);
            canvas.drawCircle(f3, f4, f5, paint);
        }
        float f6 = this.f10407J.f10454d * 0.5f;
        this.f10406I.setStyle(Paint.Style.STROKE);
        this.f10406I.setColor(this.f10407J.f10452b);
        this.f10406I.setStrokeWidth((f6 * 2.0f) + this.f10441t);
        m4590d(canvas, this.f10433l + f6, this.f10434m + f6, this.f10435n - f6, this.f10436o - f6, this.f10430i, this.f10406I);
        this.f10406I.setStyle(Paint.Style.FILL);
        this.f10406I.setStrokeWidth(1.0f);
        float f7 = this.f10433l;
        float f8 = this.f10434m;
        float f9 = this.f10430i;
        canvas.drawArc(f7, f8, (f9 * 2.0f) + f7, (f9 * 2.0f) + f8, 90.0f, 180.0f, true, this.f10406I);
        float f10 = this.f10433l;
        float f11 = this.f10430i;
        float f12 = this.f10434m;
        canvas.drawRect(f10 + f11, f12, this.f10407J.f10451a, (f11 * 2.0f) + f12, this.f10406I);
        if (this.f10418U) {
            int i3 = this.f10407J.f10453c;
            float f13 = this.f10443v;
            float f14 = this.f10433l + this.f10430i;
            float f15 = f14 - this.f10399B;
            float f16 = this.f10437p;
            float f17 = this.f10444w;
            Paint paint2 = this.f10406I;
            paint2.setStyle(Paint.Style.STROKE);
            paint2.setColor(i3);
            paint2.setStrokeWidth(f13);
            canvas.drawLine(f15, f16 - f17, f14 - this.f10400C, f16 + f17, paint2);
        }
        float f18 = this.f10407J.f10451a;
        float f19 = this.f10437p;
        canvas.drawCircle(f18, f19, this.f10431j, this.f10405H);
        this.f10406I.setStyle(Paint.Style.STROKE);
        this.f10406I.setStrokeWidth(1.0f);
        this.f10406I.setColor(-2236963);
        canvas.drawCircle(f18, f19, this.f10431j, this.f10406I);
        if (this.f10415R) {
            Paint paint3 = new Paint();
            paint3.setStyle(Paint.Style.FILL);
            paint3.setStrokeWidth(4.0f);
            paint3.setTextAlign(Paint.Align.CENTER);
            paint3.setTextSize((int) ((getContext().getResources().getDisplayMetrics().scaledDensity * 10.0f) + 0.5f));
            paint3.setColor(ViewCompat.MEASURED_STATE_MASK);
            Paint.FontMetrics fontMetrics = paint3.getFontMetrics();
            float f20 = fontMetrics.bottom;
            float f21 = (((f20 - fontMetrics.top) / 2.0f) - f20) + f19;
            paint3.getTextBounds("弹幕", 0, 2, new Rect());
            canvas.drawText("弹幕", f18, f21, paint3);
        }
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        int mode = View.MeasureSpec.getMode(i2);
        int mode2 = View.MeasureSpec.getMode(i3);
        if (mode == 0 || mode == Integer.MIN_VALUE) {
            i2 = View.MeasureSpec.makeMeasureSpec(f10396c, 1073741824);
        }
        if (mode2 == 0 || mode2 == Integer.MIN_VALUE) {
            i3 = View.MeasureSpec.makeMeasureSpec(f10397e, 1073741824);
        }
        super.onMeasure(i2, i3);
    }

    @Override // android.view.View
    public void onSizeChanged(int i2, int i3, int i4, int i5) {
        super.onSizeChanged(i2, i3, i4, i5);
        float max = Math.max(this.f10426f + this.f10428g, this.f10441t);
        float f2 = i3 - max;
        float f3 = f2 - max;
        this.f10432k = f3;
        float f4 = i2 - max;
        float f5 = f3 * 0.5f;
        this.f10430i = f5;
        this.f10431j = f5 - this.f10441t;
        this.f10433l = max;
        this.f10434m = max;
        this.f10435n = f4;
        this.f10436o = f2;
        this.f10437p = (f2 + max) * 0.5f;
        this.f10403F = max + f5;
        this.f10404G = f4 - f5;
        if (isChecked()) {
            setCheckedViewState(this.f10407J);
        } else {
            setUncheckViewState(this.f10407J);
        }
        this.f10420W = true;
        postInvalidate();
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (!isEnabled()) {
            return false;
        }
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 0) {
            this.f10419V = true;
            this.f10423c0 = System.currentTimeMillis();
            removeCallbacks(this.f10424d0);
            postDelayed(this.f10424d0, 100L);
        } else if (actionMasked == 1) {
            this.f10419V = false;
            removeCallbacks(this.f10424d0);
            if (System.currentTimeMillis() - this.f10423c0 <= 300) {
                toggle();
            } else if (m4592f()) {
                boolean z = Math.max(0.0f, Math.min(1.0f, motionEvent.getX() / ((float) getWidth()))) > 0.5f;
                if (z == isChecked()) {
                    m4594k();
                } else {
                    this.f10414Q = z;
                    if (this.f10412O.isRunning()) {
                        this.f10412O.cancel();
                    }
                    this.f10411N = 4;
                    C4063e.m4597a(this.f10408K, this.f10407J);
                    if (isChecked()) {
                        setCheckedViewState(this.f10409L);
                    } else {
                        setUncheckViewState(this.f10409L);
                    }
                    this.f10412O.start();
                }
            } else if (m4593g()) {
                m4594k();
            }
        } else if (actionMasked == 2) {
            float x = motionEvent.getX();
            if (m4593g()) {
                float max = Math.max(0.0f, Math.min(1.0f, x / getWidth()));
                C4063e c4063e = this.f10407J;
                float f2 = this.f10403F;
                c4063e.f10451a = C1499a.m627m(this.f10404G, f2, max, f2);
            } else if (m4592f()) {
                float max2 = Math.max(0.0f, Math.min(1.0f, x / getWidth()));
                C4063e c4063e2 = this.f10407J;
                float f3 = this.f10403F;
                c4063e2.f10451a = C1499a.m627m(this.f10404G, f3, max2, f3);
                c4063e2.f10452b = ((Integer) this.f10413P.evaluate(max2, Integer.valueOf(this.f10439r), Integer.valueOf(this.f10440s))).intValue();
                postInvalidate();
            }
        } else if (actionMasked == 3) {
            this.f10419V = false;
            removeCallbacks(this.f10424d0);
            if (m4593g() || m4592f()) {
                m4594k();
            }
        }
        return true;
    }

    @Override // android.widget.Checkable
    public void setChecked(boolean z) {
        if (z == isChecked()) {
            postInvalidate();
        } else {
            m4595l(this.f10416S, false);
        }
    }

    public void setEnableEffect(boolean z) {
        this.f10416S = z;
    }

    public void setOnCheckedChangeListener(InterfaceC4062d interfaceC4062d) {
        this.f10422b0 = interfaceC4062d;
    }

    @Override // android.view.View
    public final void setOnClickListener(View.OnClickListener onClickListener) {
    }

    @Override // android.view.View
    public final void setOnLongClickListener(View.OnLongClickListener onLongClickListener) {
    }

    @Override // android.view.View
    public final void setPadding(int i2, int i3, int i4, int i5) {
        super.setPadding(0, 0, 0, 0);
    }

    public void setShadowEffect(boolean z) {
        if (this.f10417T == z) {
            return;
        }
        this.f10417T = z;
        if (z) {
            this.f10405H.setShadowLayer(this.f10426f, 0.0f, this.f10428g, this.f10429h);
        } else {
            this.f10405H.setShadowLayer(0.0f, 0.0f, 0.0f, 0);
        }
    }

    @Override // android.widget.Checkable
    public void toggle() {
        m4595l(true, true);
    }

    public SwitchButton(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f10410M = new RectF();
        this.f10411N = 0;
        this.f10413P = new ArgbEvaluator();
        this.f10419V = false;
        this.f10420W = false;
        this.f10421a0 = false;
        this.f10424d0 = new RunnableC4059a();
        this.f10425e0 = new C4060b();
        this.f10427f0 = new C4061c();
        m4591e(context, attributeSet);
    }

    public SwitchButton(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f10410M = new RectF();
        this.f10411N = 0;
        this.f10413P = new ArgbEvaluator();
        this.f10419V = false;
        this.f10420W = false;
        this.f10421a0 = false;
        this.f10424d0 = new RunnableC4059a();
        this.f10425e0 = new C4060b();
        this.f10427f0 = new C4061c();
        m4591e(context, attributeSet);
    }
}
