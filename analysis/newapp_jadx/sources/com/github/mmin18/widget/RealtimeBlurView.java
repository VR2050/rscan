package com.github.mmin18.widget;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewTreeObserver;
import com.github.mmin18.realtimeblurview.R$styleable;
import p005b.p190k.p197c.p198a.C1900a;
import p005b.p190k.p197c.p198a.C1901b;
import p005b.p190k.p197c.p198a.C1903d;
import p005b.p190k.p197c.p198a.C1904e;
import p005b.p190k.p197c.p198a.InterfaceC1902c;

/* loaded from: classes.dex */
public class RealtimeBlurView extends View {

    /* renamed from: c */
    public static int f9211c;

    /* renamed from: e */
    public static int f9212e;

    /* renamed from: f */
    public static C3258b f9213f = new C3258b(null);

    /* renamed from: g */
    public float f9214g;

    /* renamed from: h */
    public int f9215h;

    /* renamed from: i */
    public float f9216i;

    /* renamed from: j */
    public final InterfaceC1902c f9217j;

    /* renamed from: k */
    public boolean f9218k;

    /* renamed from: l */
    public Bitmap f9219l;

    /* renamed from: m */
    public Bitmap f9220m;

    /* renamed from: n */
    public Canvas f9221n;

    /* renamed from: o */
    public boolean f9222o;

    /* renamed from: p */
    public Paint f9223p;

    /* renamed from: q */
    public final Rect f9224q;

    /* renamed from: r */
    public final Rect f9225r;

    /* renamed from: s */
    public View f9226s;

    /* renamed from: t */
    public boolean f9227t;

    /* renamed from: u */
    public final ViewTreeObserver.OnPreDrawListener f9228u;

    /* renamed from: com.github.mmin18.widget.RealtimeBlurView$a */
    public class ViewTreeObserverOnPreDrawListenerC3257a implements ViewTreeObserver.OnPreDrawListener {
        public ViewTreeObserverOnPreDrawListenerC3257a() {
        }

        /* JADX WARN: Removed duplicated region for block: B:10:0x009b  */
        @Override // android.view.ViewTreeObserver.OnPreDrawListener
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean onPreDraw() {
            /*
                Method dump skipped, instructions count: 357
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.github.mmin18.widget.RealtimeBlurView.ViewTreeObserverOnPreDrawListenerC3257a.onPreDraw():boolean");
        }
    }

    /* renamed from: com.github.mmin18.widget.RealtimeBlurView$b */
    public static class C3258b extends RuntimeException {
        public C3258b(ViewTreeObserverOnPreDrawListenerC3257a viewTreeObserverOnPreDrawListenerC3257a) {
        }
    }

    public RealtimeBlurView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f9224q = new Rect();
        this.f9225r = new Rect();
        this.f9228u = new ViewTreeObserverOnPreDrawListenerC3257a();
        this.f9217j = getBlurImpl();
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.RealtimeBlurView);
        this.f9216i = obtainStyledAttributes.getDimension(R$styleable.RealtimeBlurView_realtimeBlurRadius, TypedValue.applyDimension(1, 10.0f, context.getResources().getDisplayMetrics()));
        this.f9214g = obtainStyledAttributes.getFloat(R$styleable.RealtimeBlurView_realtimeDownsampleFactor, 4.0f);
        this.f9215h = obtainStyledAttributes.getColor(R$styleable.RealtimeBlurView_realtimeOverlayColor, -1426063361);
        obtainStyledAttributes.recycle();
        this.f9223p = new Paint();
    }

    /* renamed from: a */
    public static /* synthetic */ int m4021a() {
        int i2 = f9211c;
        f9211c = i2 - 1;
        return i2;
    }

    /* renamed from: b */
    public void m4022b() {
        m4023c();
        this.f9217j.release();
    }

    /* renamed from: c */
    public final void m4023c() {
        Bitmap bitmap = this.f9219l;
        if (bitmap != null) {
            bitmap.recycle();
            this.f9219l = null;
        }
        Bitmap bitmap2 = this.f9220m;
        if (bitmap2 != null) {
            bitmap2.recycle();
            this.f9220m = null;
        }
    }

    @Override // android.view.View
    public void draw(Canvas canvas) {
        if (this.f9222o) {
            throw f9213f;
        }
        if (f9211c > 0) {
            return;
        }
        super.draw(canvas);
    }

    public View getActivityDecorView() {
        Context context = getContext();
        for (int i2 = 0; i2 < 4 && context != null && !(context instanceof Activity) && (context instanceof ContextWrapper); i2++) {
            context = ((ContextWrapper) context).getBaseContext();
        }
        if (context instanceof Activity) {
            return ((Activity) context).getWindow().getDecorView();
        }
        return null;
    }

    public InterfaceC1902c getBlurImpl() {
        if (f9212e == 0) {
            try {
                C1900a c1900a = new C1900a();
                Bitmap createBitmap = Bitmap.createBitmap(4, 4, Bitmap.Config.ARGB_8888);
                c1900a.mo1252b(getContext(), createBitmap, 4.0f);
                c1900a.release();
                createBitmap.recycle();
                f9212e = 3;
            } catch (Throwable unused) {
            }
        }
        if (f9212e == 0) {
            try {
                getClass().getClassLoader().loadClass("androidx.renderscript.RenderScript");
                C1901b c1901b = new C1901b();
                Bitmap createBitmap2 = Bitmap.createBitmap(4, 4, Bitmap.Config.ARGB_8888);
                c1901b.mo1252b(getContext(), createBitmap2, 4.0f);
                c1901b.release();
                createBitmap2.recycle();
                f9212e = 1;
            } catch (Throwable unused2) {
            }
        }
        if (f9212e == 0) {
            try {
                getClass().getClassLoader().loadClass("androidx.renderscript.RenderScript");
                C1904e c1904e = new C1904e();
                Bitmap createBitmap3 = Bitmap.createBitmap(4, 4, Bitmap.Config.ARGB_8888);
                c1904e.mo1252b(getContext(), createBitmap3, 4.0f);
                c1904e.release();
                createBitmap3.recycle();
                f9212e = 2;
            } catch (Throwable unused3) {
            }
        }
        if (f9212e == 0) {
            f9212e = -1;
        }
        int i2 = f9212e;
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? new C1903d() : new C1900a() : new C1904e() : new C1901b();
    }

    @Override // android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        View activityDecorView = getActivityDecorView();
        this.f9226s = activityDecorView;
        if (activityDecorView == null) {
            this.f9227t = false;
            return;
        }
        activityDecorView.getViewTreeObserver().addOnPreDrawListener(this.f9228u);
        boolean z = this.f9226s.getRootView() != getRootView();
        this.f9227t = z;
        if (z) {
            this.f9226s.postInvalidate();
        }
    }

    @Override // android.view.View
    public void onDetachedFromWindow() {
        View view = this.f9226s;
        if (view != null) {
            view.getViewTreeObserver().removeOnPreDrawListener(this.f9228u);
        }
        m4022b();
        super.onDetachedFromWindow();
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        Bitmap bitmap = this.f9220m;
        int i2 = this.f9215h;
        if (bitmap != null) {
            this.f9224q.right = bitmap.getWidth();
            this.f9224q.bottom = bitmap.getHeight();
            this.f9225r.right = getWidth();
            this.f9225r.bottom = getHeight();
            canvas.drawBitmap(bitmap, this.f9224q, this.f9225r, (Paint) null);
        }
        this.f9223p.setColor(i2);
        canvas.drawRect(this.f9225r, this.f9223p);
    }

    public void setBlurRadius(float f2) {
        if (this.f9216i != f2) {
            this.f9216i = f2;
            this.f9218k = true;
            invalidate();
        }
    }

    public void setDownsampleFactor(float f2) {
        if (f2 <= 0.0f) {
            throw new IllegalArgumentException("Downsample factor must be greater than 0.");
        }
        if (this.f9214g != f2) {
            this.f9214g = f2;
            this.f9218k = true;
            m4023c();
            invalidate();
        }
    }

    public void setOverlayColor(int i2) {
        if (this.f9215h != i2) {
            this.f9215h = i2;
            invalidate();
        }
    }
}
