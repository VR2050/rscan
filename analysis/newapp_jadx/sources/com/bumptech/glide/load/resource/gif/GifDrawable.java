package com.bumptech.glide.load.resource.gif;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.view.Gravity;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import androidx.vectordrawable.graphics.drawable.Animatable2Compat;
import java.util.ArrayList;
import java.util.List;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p146l.InterfaceC1564a;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p156v.p161g.C1736f;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class GifDrawable extends Drawable implements C1736f.b, Animatable, Animatable2Compat {

    /* renamed from: c */
    public final C3221a f8843c;

    /* renamed from: e */
    public boolean f8844e;

    /* renamed from: f */
    public boolean f8845f;

    /* renamed from: g */
    public boolean f8846g;

    /* renamed from: h */
    public boolean f8847h;

    /* renamed from: i */
    public int f8848i;

    /* renamed from: j */
    public int f8849j;

    /* renamed from: k */
    public boolean f8850k;

    /* renamed from: l */
    public Paint f8851l;

    /* renamed from: m */
    public Rect f8852m;

    /* renamed from: n */
    public List<Animatable2Compat.AnimationCallback> f8853n;

    /* renamed from: com.bumptech.glide.load.resource.gif.GifDrawable$a */
    public static final class C3221a extends Drawable.ConstantState {

        /* renamed from: a */
        @VisibleForTesting
        public final C1736f f8854a;

        public C3221a(C1736f c1736f) {
            this.f8854a = c1736f;
        }

        @Override // android.graphics.drawable.Drawable.ConstantState
        public int getChangingConfigurations() {
            return 0;
        }

        @Override // android.graphics.drawable.Drawable.ConstantState
        @NonNull
        public Drawable newDrawable() {
            return new GifDrawable(this);
        }

        @Override // android.graphics.drawable.Drawable.ConstantState
        @NonNull
        public Drawable newDrawable(Resources resources) {
            return new GifDrawable(this);
        }
    }

    public GifDrawable(Context context, InterfaceC1564a interfaceC1564a, InterfaceC1586r<Bitmap> interfaceC1586r, int i2, int i3, Bitmap bitmap) {
        C3221a c3221a = new C3221a(new C1736f(ComponentCallbacks2C1553c.m735d(context), interfaceC1564a, i2, i3, interfaceC1586r, bitmap));
        this.f8847h = true;
        this.f8849j = -1;
        this.f8843c = c3221a;
    }

    @Override // p005b.p143g.p144a.p147m.p156v.p161g.C1736f.b
    /* renamed from: a */
    public void mo1035a() {
        Object callback = getCallback();
        while (callback instanceof Drawable) {
            callback = ((Drawable) callback).getCallback();
        }
        if (callback == null) {
            stop();
            invalidateSelf();
            return;
        }
        invalidateSelf();
        C1736f.a aVar = this.f8843c.f8854a.f2575i;
        if ((aVar != null ? aVar.f2586e : -1) == r0.f2567a.mo806c() - 1) {
            this.f8848i++;
        }
        int i2 = this.f8849j;
        if (i2 == -1 || this.f8848i < i2) {
            return;
        }
        List<Animatable2Compat.AnimationCallback> list = this.f8853n;
        if (list != null) {
            int size = list.size();
            for (int i3 = 0; i3 < size; i3++) {
                this.f8853n.get(i3).onAnimationEnd(this);
            }
        }
        stop();
    }

    /* renamed from: b */
    public Bitmap m3892b() {
        return this.f8843c.f8854a.f2578l;
    }

    /* renamed from: c */
    public final Paint m3893c() {
        if (this.f8851l == null) {
            this.f8851l = new Paint(2);
        }
        return this.f8851l;
    }

    @Override // androidx.vectordrawable.graphics.drawable.Animatable2Compat
    public void clearAnimationCallbacks() {
        List<Animatable2Compat.AnimationCallback> list = this.f8853n;
        if (list != null) {
            list.clear();
        }
    }

    /* renamed from: d */
    public final void m3894d() {
        C4195m.m4763E(!this.f8846g, "You cannot start a recycled Drawable. Ensure thatyou clear any references to the Drawable when clearing the corresponding request.");
        if (this.f8843c.f8854a.f2567a.mo806c() == 1) {
            invalidateSelf();
            return;
        }
        if (this.f8844e) {
            return;
        }
        this.f8844e = true;
        C1736f c1736f = this.f8843c.f8854a;
        if (c1736f.f2576j) {
            throw new IllegalStateException("Cannot subscribe to a cleared frame loader");
        }
        if (c1736f.f2569c.contains(this)) {
            throw new IllegalStateException("Cannot subscribe twice in a row");
        }
        boolean isEmpty = c1736f.f2569c.isEmpty();
        c1736f.f2569c.add(this);
        if (isEmpty && !c1736f.f2572f) {
            c1736f.f2572f = true;
            c1736f.f2576j = false;
            c1736f.m1032a();
        }
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(@NonNull Canvas canvas) {
        if (this.f8846g) {
            return;
        }
        if (this.f8850k) {
            int intrinsicWidth = getIntrinsicWidth();
            int intrinsicHeight = getIntrinsicHeight();
            Rect bounds = getBounds();
            if (this.f8852m == null) {
                this.f8852m = new Rect();
            }
            Gravity.apply(119, intrinsicWidth, intrinsicHeight, bounds, this.f8852m);
            this.f8850k = false;
        }
        C1736f c1736f = this.f8843c.f8854a;
        C1736f.a aVar = c1736f.f2575i;
        Bitmap bitmap = aVar != null ? aVar.f2588g : c1736f.f2578l;
        if (this.f8852m == null) {
            this.f8852m = new Rect();
        }
        canvas.drawBitmap(bitmap, (Rect) null, this.f8852m, m3893c());
    }

    /* renamed from: e */
    public final void m3895e() {
        this.f8844e = false;
        C1736f c1736f = this.f8843c.f8854a;
        c1736f.f2569c.remove(this);
        if (c1736f.f2569c.isEmpty()) {
            c1736f.f2572f = false;
        }
    }

    @Override // android.graphics.drawable.Drawable
    public Drawable.ConstantState getConstantState() {
        return this.f8843c;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return this.f8843c.f8854a.f2584r;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return this.f8843c.f8854a.f2583q;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -2;
    }

    @Override // android.graphics.drawable.Animatable
    public boolean isRunning() {
        return this.f8844e;
    }

    @Override // android.graphics.drawable.Drawable
    public void onBoundsChange(Rect rect) {
        super.onBoundsChange(rect);
        this.f8850k = true;
    }

    @Override // androidx.vectordrawable.graphics.drawable.Animatable2Compat
    public void registerAnimationCallback(@NonNull Animatable2Compat.AnimationCallback animationCallback) {
        if (animationCallback == null) {
            return;
        }
        if (this.f8853n == null) {
            this.f8853n = new ArrayList();
        }
        this.f8853n.add(animationCallback);
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i2) {
        m3893c().setAlpha(i2);
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        m3893c().setColorFilter(colorFilter);
    }

    @Override // android.graphics.drawable.Drawable
    public boolean setVisible(boolean z, boolean z2) {
        C4195m.m4763E(!this.f8846g, "Cannot change the visibility of a recycled resource. Ensure that you unset the Drawable from your View before changing the View's visibility.");
        this.f8847h = z;
        if (!z) {
            m3895e();
        } else if (this.f8845f) {
            m3894d();
        }
        return super.setVisible(z, z2);
    }

    @Override // android.graphics.drawable.Animatable
    public void start() {
        this.f8845f = true;
        this.f8848i = 0;
        if (this.f8847h) {
            m3894d();
        }
    }

    @Override // android.graphics.drawable.Animatable
    public void stop() {
        this.f8845f = false;
        m3895e();
    }

    @Override // androidx.vectordrawable.graphics.drawable.Animatable2Compat
    public boolean unregisterAnimationCallback(@NonNull Animatable2Compat.AnimationCallback animationCallback) {
        List<Animatable2Compat.AnimationCallback> list = this.f8853n;
        if (list == null || animationCallback == null) {
            return false;
        }
        return list.remove(animationCallback);
    }

    public GifDrawable(C3221a c3221a) {
        this.f8847h = true;
        this.f8849j = -1;
        this.f8843c = c3221a;
    }
}
