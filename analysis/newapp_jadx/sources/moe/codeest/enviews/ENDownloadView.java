package moe.codeest.enviews;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.LinearInterpolator;
import android.view.animation.OvershootInterpolator;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.shuyu.gsyvideoplayer.R$styleable;
import p005b.p085c.p088b.p089a.C1345b;
import p455j.p456a.p457a.C4365a;
import p455j.p456a.p457a.C4366b;

/* loaded from: classes3.dex */
public class ENDownloadView extends View {

    /* renamed from: c */
    public int f12753c;

    /* renamed from: e */
    public float f12754e;

    /* renamed from: f */
    public double f12755f;

    /* renamed from: g */
    public int f12756g;

    /* renamed from: h */
    public int f12757h;

    /* renamed from: i */
    public int f12758i;

    /* renamed from: j */
    public Paint f12759j;

    /* renamed from: k */
    public Paint f12760k;

    /* renamed from: l */
    public Paint f12761l;

    /* renamed from: m */
    public Path f12762m;

    /* renamed from: n */
    public RectF f12763n;

    /* renamed from: o */
    public RectF f12764o;

    /* renamed from: p */
    public ValueAnimator f12765p;

    /* renamed from: q */
    public float f12766q;

    /* renamed from: r */
    public float f12767r;

    /* renamed from: s */
    public float f12768s;

    /* renamed from: t */
    public float f12769t;

    /* renamed from: u */
    public float f12770u;

    /* renamed from: v */
    public float f12771v;

    /* renamed from: w */
    public float f12772w;

    /* renamed from: x */
    public float f12773x;

    /* renamed from: moe.codeest.enviews.ENDownloadView$a */
    public class C4973a implements ValueAnimator.AnimatorUpdateListener {
        public C4973a() {
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            ENDownloadView.this.f12766q = valueAnimator.getAnimatedFraction();
            ENDownloadView.this.invalidate();
        }
    }

    /* renamed from: moe.codeest.enviews.ENDownloadView$b */
    public class C4974b extends AnimatorListenerAdapter {
        public C4974b() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            ENDownloadView eNDownloadView = ENDownloadView.this;
            eNDownloadView.f12753c = 1;
            ENDownloadView.m5643a(eNDownloadView);
        }
    }

    /* renamed from: moe.codeest.enviews.ENDownloadView$c */
    public interface InterfaceC4975c {
    }

    public ENDownloadView(Context context) {
        super(context);
    }

    /* renamed from: a */
    public static void m5643a(ENDownloadView eNDownloadView) {
        ValueAnimator valueAnimator = eNDownloadView.f12765p;
        if (valueAnimator != null) {
            valueAnimator.removeAllListeners();
            eNDownloadView.f12765p.removeAllUpdateListeners();
            if (eNDownloadView.f12765p.isRunning()) {
                eNDownloadView.f12765p.cancel();
            }
            eNDownloadView.f12765p = null;
        }
        if (eNDownloadView.f12753c != 1) {
            return;
        }
        ValueAnimator ofFloat = ValueAnimator.ofFloat(1.0f, 100.0f);
        eNDownloadView.f12765p = ofFloat;
        ofFloat.setDuration(eNDownloadView.f12757h);
        eNDownloadView.f12765p.setInterpolator(new LinearInterpolator());
        eNDownloadView.f12765p.addUpdateListener(new C4365a(eNDownloadView));
        eNDownloadView.f12765p.addListener(new C4366b(eNDownloadView));
        eNDownloadView.f12765p.start();
    }

    /* renamed from: b */
    public void m5644b() {
        this.f12766q = 0.0f;
        this.f12753c = 0;
        ValueAnimator valueAnimator = this.f12765p;
        if (valueAnimator != null) {
            valueAnimator.removeAllListeners();
            this.f12765p.removeAllUpdateListeners();
            if (this.f12765p.isRunning()) {
                this.f12765p.cancel();
            }
            this.f12765p = null;
        }
    }

    /* renamed from: c */
    public void m5645c() {
        ValueAnimator valueAnimator = this.f12765p;
        if (valueAnimator != null) {
            valueAnimator.removeAllListeners();
            this.f12765p.removeAllUpdateListeners();
            if (this.f12765p.isRunning()) {
                this.f12765p.cancel();
            }
            this.f12765p = null;
        }
        this.f12753c = 1;
        ValueAnimator ofFloat = ValueAnimator.ofFloat(1.0f, 100.0f);
        this.f12765p = ofFloat;
        ofFloat.setDuration(1500L);
        this.f12765p.setInterpolator(new OvershootInterpolator());
        this.f12765p.addUpdateListener(new C4973a());
        this.f12765p.addListener(new C4974b());
        this.f12765p.start();
    }

    public int getCurrentState() {
        return this.f12753c;
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int i2 = this.f12753c;
        if (i2 == 0) {
            float f2 = this.f12766q;
            double d2 = f2;
            if (d2 <= 0.4d) {
                canvas.drawCircle(this.f12769t, this.f12770u, this.f12772w, this.f12760k);
                float f3 = this.f12769t;
                float f4 = this.f12771v;
                float f5 = this.f12770u;
                canvas.drawLine(f3 - f4, f5, f3, f5 + f4, this.f12759j);
                float f6 = this.f12769t;
                float f7 = this.f12770u;
                float f8 = this.f12771v;
                canvas.drawLine(f6, f7 + f8, f6 + f8, f7, this.f12759j);
                float f9 = this.f12769t;
                float f10 = this.f12770u;
                float f11 = this.f12771v;
                float f12 = ((1.3f * f11) / 0.4f) * this.f12766q;
                canvas.drawLine(f9, (f10 + f11) - f12, f9, f12 + (f10 - (f11 * 1.6f)), this.f12759j);
                return;
            }
            if (d2 <= 0.6d) {
                canvas.drawCircle(this.f12769t, this.f12770u, this.f12772w, this.f12760k);
                canvas.drawCircle(this.f12769t, this.f12770u - (this.f12771v * 0.3f), 2.0f, this.f12759j);
                float f13 = this.f12769t;
                float f14 = this.f12771v;
                float f15 = this.f12766q - 0.4f;
                float f16 = this.f12770u;
                canvas.drawLine((f13 - f14) - (((1.2f * f14) / 0.2f) * f15), f16, f13, (f16 + f14) - ((f14 / 0.2f) * f15), this.f12759j);
                float f17 = this.f12769t;
                float f18 = this.f12770u;
                float f19 = this.f12771v;
                float f20 = this.f12766q - 0.4f;
                canvas.drawLine(f17, (f18 + f19) - ((f19 / 0.2f) * f20), f17 + f19 + (((f19 * 1.2f) / 0.2f) * f20), f18, this.f12759j);
                return;
            }
            if (f2 > 1.0f) {
                canvas.drawCircle(this.f12769t, this.f12770u, this.f12772w, this.f12760k);
                canvas.drawCircle(this.f12769t, (this.f12770u - this.f12772w) - ((this.f12766q - 1.0f) * (this.f12771v * 3.0f)), 3.0f, this.f12759j);
                float f21 = this.f12769t;
                float f22 = this.f12771v * 2.2f;
                float f23 = this.f12770u;
                canvas.drawLine(f21 - f22, f23, f22 + f21, f23, this.f12759j);
                return;
            }
            canvas.drawCircle(this.f12769t, this.f12770u, this.f12772w, this.f12760k);
            float f24 = this.f12769t;
            float f25 = this.f12770u;
            float f26 = this.f12771v * 0.3f;
            canvas.drawCircle(f24, (f25 - f26) - ((this.f12766q - 0.6f) * ((this.f12772w - f26) / 0.4f)), 2.0f, this.f12759j);
            float f27 = this.f12769t;
            float f28 = this.f12771v * 2.2f;
            float f29 = this.f12770u;
            canvas.drawLine(f27 - f28, f29, f28 + f27, f29, this.f12759j);
            return;
        }
        if (i2 == 1) {
            float f30 = this.f12766q;
            if (f30 <= 0.2d) {
                this.f12761l.setTextSize((this.f12756g / 0.2f) * f30);
            }
            canvas.drawCircle(this.f12769t, this.f12770u, this.f12772w, this.f12760k);
            canvas.drawArc(this.f12763n, -90.0f, this.f12766q * 359.99f, false, this.f12759j);
            this.f12762m.reset();
            float f31 = this.f12754e + 2.0f;
            this.f12754e = f31;
            float f32 = this.f12769t;
            float f33 = this.f12773x;
            if (f31 > f32 - (6.0f * f33)) {
                this.f12754e = f32 - (f33 * 10.0f);
            }
            this.f12762m.moveTo(this.f12754e, this.f12770u);
            for (int i3 = 0; i3 < 4; i3++) {
                Path path = this.f12762m;
                float f34 = this.f12773x;
                path.rQuadTo(f34, (-(1.0f - this.f12766q)) * f34, f34 * 2.0f, 0.0f);
                Path path2 = this.f12762m;
                float f35 = this.f12773x;
                path2.rQuadTo(f35, (1.0f - this.f12766q) * f35, f35 * 2.0f, 0.0f);
            }
            canvas.save();
            canvas.clipRect(this.f12764o);
            canvas.drawPath(this.f12762m, this.f12759j);
            canvas.restore();
            return;
        }
        if (i2 != 2) {
            if (i2 != 3) {
                return;
            }
            canvas.drawCircle(this.f12769t, this.f12770u, this.f12772w, this.f12760k);
            float f36 = this.f12769t;
            float f37 = this.f12771v;
            float f38 = this.f12770u;
            float f39 = f37 * 0.5f;
            float f40 = this.f12766q;
            canvas.drawLine(f36 - f37, f38, (f39 * f40) + (f36 - f39), (f37 * 0.35f * f40) + (f37 * 0.65f) + f38, this.f12759j);
            float f41 = this.f12769t;
            float f42 = this.f12771v;
            float f43 = f42 * 0.5f;
            float f44 = this.f12766q;
            float f45 = this.f12770u;
            float f46 = (f42 * 0.65f) + f45 + (f42 * 0.35f * f44);
            float f47 = ((1.2f * f42) + f41) - ((0.2f * f42) * f44);
            float f48 = f42 * 1.3f;
            canvas.drawLine((f43 * f44) + (f41 - f43), f46, f47, (f48 * f44) + (f45 - f48), this.f12759j);
            float f49 = this.f12769t;
            float f50 = this.f12771v;
            float f51 = 0.5f * f50;
            float f52 = this.f12766q;
            float f53 = (f51 * f52) + (f49 - f51);
            float f54 = (0.65f * f50) + this.f12770u;
            canvas.drawLine(f53, (0.35f * f50 * f52) + f54, f53, f54 - ((f50 * 2.25f) * f52), this.f12759j);
            return;
        }
        canvas.drawCircle(this.f12769t, this.f12770u, this.f12772w, this.f12759j);
        float f55 = this.f12766q;
        if (f55 <= 0.5d) {
            Paint paint = this.f12761l;
            float f56 = this.f12756g;
            paint.setTextSize(f56 - ((f56 / 0.2f) * f55));
        } else {
            this.f12761l.setTextSize(0.0f);
        }
        if (this.f12758i != 5 && this.f12755f > ShadowDrawableWrapper.COS_45) {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%.2f", Double.valueOf(this.f12755f)));
            int m350b = C1345b.m350b(this.f12758i);
            sb.append(m350b != 0 ? m350b != 1 ? m350b != 2 ? " b" : " kb" : " mb" : " gb");
            canvas.drawText(sb.toString(), this.f12769t, (this.f12771v * 1.4f) + this.f12770u, this.f12761l);
        }
        float f57 = this.f12769t;
        float f58 = this.f12771v;
        float f59 = this.f12766q;
        float f60 = (f57 - (f58 * 2.2f)) + (1.2f * f58 * f59);
        float f61 = this.f12770u;
        float f62 = f58 * 0.5f;
        canvas.drawLine(f60, f61, f57 - f62, (f62 * f59 * 1.3f) + f61, this.f12759j);
        float f63 = this.f12769t;
        float f64 = this.f12771v;
        float f65 = 0.5f * f64;
        float f66 = this.f12770u;
        float f67 = this.f12766q;
        float f68 = (2.2f * f64) + f63;
        float f69 = f64 * f67;
        canvas.drawLine(f63 - f65, (f65 * f67 * 1.3f) + f66, f68 - f69, f66 - (f69 * 1.3f), this.f12759j);
    }

    @Override // android.view.View
    public void onSizeChanged(int i2, int i3, int i4, int i5) {
        super.onSizeChanged(i2, i3, i4, i5);
        float f2 = i2;
        this.f12767r = f2;
        float f3 = i3;
        this.f12768s = f3;
        float f4 = f2 / 2.0f;
        this.f12769t = f4;
        this.f12770u = f3 / 2.0f;
        float f5 = (f2 * 5.0f) / 12.0f;
        this.f12772w = f5;
        float f6 = f5 / 3.0f;
        this.f12771v = f6;
        float f7 = (f6 * 4.4f) / 12.0f;
        this.f12773x = f7;
        this.f12754e = f4 - (f7 * 10.0f);
        float f8 = this.f12769t;
        float f9 = this.f12772w;
        float f10 = this.f12770u;
        this.f12763n = new RectF(f8 - f9, f10 - f9, f8 + f9, f10 + f9);
        float f11 = this.f12769t;
        float f12 = this.f12773x;
        this.f12764o = new RectF(f11 - (f12 * 6.0f), 0.0f, (f12 * 6.0f) + f11, this.f12768s);
    }

    public void setOnDownloadStateListener(InterfaceC4975c interfaceC4975c) {
    }

    public ENDownloadView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.download);
        int color = obtainStyledAttributes.getColor(R$styleable.download_download_line_color, -1);
        int color2 = obtainStyledAttributes.getColor(R$styleable.download_download_bg_line_color, -12959931);
        int color3 = obtainStyledAttributes.getColor(R$styleable.download_download_text_color, -1);
        int integer = obtainStyledAttributes.getInteger(R$styleable.download_download_line_width, 9);
        int integer2 = obtainStyledAttributes.getInteger(R$styleable.download_download_bg_line_width, 9);
        int integer3 = obtainStyledAttributes.getInteger(R$styleable.download_download_text_size, 14);
        obtainStyledAttributes.recycle();
        Paint paint = new Paint(1);
        this.f12759j = paint;
        paint.setStyle(Paint.Style.STROKE);
        this.f12759j.setStrokeCap(Paint.Cap.ROUND);
        this.f12759j.setStrokeWidth(integer);
        this.f12759j.setColor(color);
        Paint paint2 = new Paint(1);
        this.f12760k = paint2;
        paint2.setStyle(Paint.Style.STROKE);
        this.f12760k.setStrokeCap(Paint.Cap.ROUND);
        this.f12760k.setStrokeWidth(integer2);
        this.f12760k.setColor(color2);
        Paint paint3 = new Paint(1);
        this.f12761l = paint3;
        paint3.setColor(color3);
        this.f12761l.setTextSize(integer3);
        this.f12761l.setTextAlign(Paint.Align.CENTER);
        this.f12762m = new Path();
        this.f12756g = integer3;
        this.f12753c = 0;
        this.f12758i = 4;
        this.f12757h = 2000;
    }
}
