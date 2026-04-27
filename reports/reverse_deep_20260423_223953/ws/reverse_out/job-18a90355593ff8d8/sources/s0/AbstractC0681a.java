package s0;

import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/* JADX INFO: renamed from: s0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0681a extends Drawable implements Drawable.Callback, D, C {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private D f9989b;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Drawable[] f9991d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final InterfaceC0683c[] f9992e;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0684d f9990c = new C0684d();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Rect f9993f = new Rect();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f9994g = false;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f9995h = false;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f9996i = false;

    /* JADX INFO: renamed from: s0.a$a, reason: collision with other inner class name */
    class C0148a implements InterfaceC0683c {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ int f9997b;

        C0148a(int i3) {
            this.f9997b = i3;
        }

        @Override // s0.InterfaceC0683c
        public Drawable d(Drawable drawable) {
            return AbstractC0681a.this.e(this.f9997b, drawable);
        }

        @Override // s0.InterfaceC0683c
        public Drawable p() {
            return AbstractC0681a.this.b(this.f9997b);
        }
    }

    public AbstractC0681a(Drawable[] drawableArr) {
        int i3 = 0;
        X.k.g(drawableArr);
        this.f9991d = drawableArr;
        while (true) {
            Drawable[] drawableArr2 = this.f9991d;
            if (i3 >= drawableArr2.length) {
                this.f9992e = new InterfaceC0683c[drawableArr2.length];
                return;
            } else {
                C0685e.d(drawableArr2[i3], this, this);
                i3++;
            }
        }
    }

    private InterfaceC0683c a(int i3) {
        return new C0148a(i3);
    }

    public Drawable b(int i3) {
        X.k.b(Boolean.valueOf(i3 >= 0));
        X.k.b(Boolean.valueOf(i3 < this.f9991d.length));
        return this.f9991d[i3];
    }

    public InterfaceC0683c c(int i3) {
        X.k.b(Boolean.valueOf(i3 >= 0));
        X.k.b(Boolean.valueOf(i3 < this.f9992e.length));
        InterfaceC0683c[] interfaceC0683cArr = this.f9992e;
        if (interfaceC0683cArr[i3] == null) {
            interfaceC0683cArr[i3] = a(i3);
        }
        return this.f9992e[i3];
    }

    public int d() {
        return this.f9991d.length;
    }

    public Drawable e(int i3, Drawable drawable) {
        X.k.b(Boolean.valueOf(i3 >= 0));
        X.k.b(Boolean.valueOf(i3 < this.f9991d.length));
        Drawable drawable2 = this.f9991d[i3];
        if (drawable != drawable2) {
            if (drawable != null && this.f9996i) {
                drawable.mutate();
            }
            C0685e.d(this.f9991d[i3], null, null);
            C0685e.d(drawable, null, null);
            C0685e.e(drawable, this.f9990c);
            C0685e.a(drawable, this);
            C0685e.d(drawable, this, this);
            this.f9995h = false;
            this.f9991d[i3] = drawable;
            invalidateSelf();
        }
        return drawable2;
    }

    @Override // s0.D
    public void f(RectF rectF) {
        D d3 = this.f9989b;
        if (d3 != null) {
            d3.f(rectF);
        } else {
            rectF.set(getBounds());
        }
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        int i3 = 0;
        int iMax = -1;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                break;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                iMax = Math.max(iMax, drawable.getIntrinsicHeight());
            }
            i3++;
        }
        if (iMax > 0) {
            return iMax;
        }
        return -1;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        int i3 = 0;
        int iMax = -1;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                break;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                iMax = Math.max(iMax, drawable.getIntrinsicWidth());
            }
            i3++;
        }
        if (iMax > 0) {
            return iMax;
        }
        return -1;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        if (this.f9991d.length == 0) {
            return -2;
        }
        int i3 = 1;
        int iResolveOpacity = -1;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return iResolveOpacity;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                iResolveOpacity = Drawable.resolveOpacity(iResolveOpacity, drawable.getOpacity());
            }
            i3++;
        }
    }

    @Override // android.graphics.drawable.Drawable
    public boolean getPadding(Rect rect) {
        int i3 = 0;
        rect.left = 0;
        rect.top = 0;
        rect.right = 0;
        rect.bottom = 0;
        Rect rect2 = this.f9993f;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return true;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                drawable.getPadding(rect2);
                rect.left = Math.max(rect.left, rect2.left);
                rect.top = Math.max(rect.top, rect2.top);
                rect.right = Math.max(rect.right, rect2.right);
                rect.bottom = Math.max(rect.bottom, rect2.bottom);
            }
            i3++;
        }
    }

    @Override // s0.C
    public void i(D d3) {
        this.f9989b = d3;
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable drawable) {
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public boolean isStateful() {
        if (!this.f9995h) {
            this.f9994g = false;
            int i3 = 0;
            while (true) {
                Drawable[] drawableArr = this.f9991d;
                boolean z3 = true;
                if (i3 >= drawableArr.length) {
                    break;
                }
                Drawable drawable = drawableArr[i3];
                boolean z4 = this.f9994g;
                if (drawable == null || !drawable.isStateful()) {
                    z3 = false;
                }
                this.f9994g = z4 | z3;
                i3++;
            }
            this.f9995h = true;
        }
        return this.f9994g;
    }

    @Override // android.graphics.drawable.Drawable
    public Drawable mutate() {
        int i3 = 0;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                this.f9996i = true;
                return this;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                drawable.mutate();
            }
            i3++;
        }
    }

    @Override // s0.D
    public void n(Matrix matrix) {
        D d3 = this.f9989b;
        if (d3 != null) {
            d3.n(matrix);
        } else {
            matrix.reset();
        }
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        int i3 = 0;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                drawable.setBounds(rect);
            }
            i3++;
        }
    }

    @Override // android.graphics.drawable.Drawable
    protected boolean onLevelChange(int i3) {
        int i4 = 0;
        boolean z3 = false;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i4 >= drawableArr.length) {
                return z3;
            }
            Drawable drawable = drawableArr[i4];
            if (drawable != null && drawable.setLevel(i3)) {
                z3 = true;
            }
            i4++;
        }
    }

    @Override // android.graphics.drawable.Drawable
    protected boolean onStateChange(int[] iArr) {
        int i3 = 0;
        boolean z3 = false;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return z3;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null && drawable.setState(iArr)) {
                z3 = true;
            }
            i3++;
        }
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void scheduleDrawable(Drawable drawable, Runnable runnable, long j3) {
        scheduleSelf(runnable, j3);
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f9990c.c(colorFilter);
        int i3 = 0;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                drawable.setColorFilter(colorFilter);
            }
            i3++;
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setDither(boolean z3) {
        this.f9990c.d(z3);
        int i3 = 0;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                drawable.setDither(z3);
            }
            i3++;
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setFilterBitmap(boolean z3) {
        this.f9990c.e(z3);
        int i3 = 0;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                drawable.setFilterBitmap(z3);
            }
            i3++;
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setHotspot(float f3, float f4) {
        int i3 = 0;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                drawable.setHotspot(f3, f4);
            }
            i3++;
        }
    }

    @Override // android.graphics.drawable.Drawable
    public boolean setVisible(boolean z3, boolean z4) {
        boolean visible = super.setVisible(z3, z4);
        int i3 = 0;
        while (true) {
            Drawable[] drawableArr = this.f9991d;
            if (i3 >= drawableArr.length) {
                return visible;
            }
            Drawable drawable = drawableArr[i3];
            if (drawable != null) {
                drawable.setVisible(z3, z4);
            }
            i3++;
        }
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void unscheduleDrawable(Drawable drawable, Runnable runnable) {
        unscheduleSelf(runnable);
    }
}
