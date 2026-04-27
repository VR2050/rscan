package androidx.appcompat.widget;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import androidx.appcompat.widget.X;
import d.AbstractC0502a;
import e.AbstractC0510a;

/* JADX INFO: renamed from: androidx.appcompat.widget.k, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0237k {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final PorterDuff.Mode f4094b = PorterDuff.Mode.SRC_IN;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static C0237k f4095c;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private X f4096a;

    /* JADX INFO: renamed from: androidx.appcompat.widget.k$a */
    class a implements X.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int[] f4097a = {d.e.f8850R, d.e.f8848P, d.e.f8852a};

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int[] f4098b = {d.e.f8866o, d.e.f8834B, d.e.f8871t, d.e.f8867p, d.e.f8868q, d.e.f8870s, d.e.f8869r};

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int[] f4099c = {d.e.f8847O, d.e.f8849Q, d.e.f8862k, d.e.f8843K, d.e.f8844L, d.e.f8845M, d.e.f8846N};

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int[] f4100d = {d.e.f8874w, d.e.f8860i, d.e.f8873v};

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final int[] f4101e = {d.e.f8842J, d.e.f8851S};

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final int[] f4102f = {d.e.f8854c, d.e.f8858g, d.e.f8855d, d.e.f8859h};

        a() {
        }

        private boolean f(int[] iArr, int i3) {
            for (int i4 : iArr) {
                if (i4 == i3) {
                    return true;
                }
            }
            return false;
        }

        private ColorStateList g(Context context) {
            return h(context, 0);
        }

        private ColorStateList h(Context context, int i3) {
            int iC = c0.c(context, AbstractC0502a.f8808t);
            return new ColorStateList(new int[][]{c0.f4037b, c0.f4040e, c0.f4038c, c0.f4044i}, new int[]{c0.b(context, AbstractC0502a.f8806r), androidx.core.graphics.a.d(iC, i3), androidx.core.graphics.a.d(iC, i3), i3});
        }

        private ColorStateList i(Context context) {
            return h(context, c0.c(context, AbstractC0502a.f8805q));
        }

        private ColorStateList j(Context context) {
            return h(context, c0.c(context, AbstractC0502a.f8806r));
        }

        private ColorStateList k(Context context) {
            int[][] iArr = new int[3][];
            int[] iArr2 = new int[3];
            ColorStateList colorStateListE = c0.e(context, AbstractC0502a.f8810v);
            if (colorStateListE == null || !colorStateListE.isStateful()) {
                iArr[0] = c0.f4037b;
                iArr2[0] = c0.b(context, AbstractC0502a.f8810v);
                iArr[1] = c0.f4041f;
                iArr2[1] = c0.c(context, AbstractC0502a.f8807s);
                iArr[2] = c0.f4044i;
                iArr2[2] = c0.c(context, AbstractC0502a.f8810v);
            } else {
                int[] iArr3 = c0.f4037b;
                iArr[0] = iArr3;
                iArr2[0] = colorStateListE.getColorForState(iArr3, 0);
                iArr[1] = c0.f4041f;
                iArr2[1] = c0.c(context, AbstractC0502a.f8807s);
                iArr[2] = c0.f4044i;
                iArr2[2] = colorStateListE.getDefaultColor();
            }
            return new ColorStateList(iArr, iArr2);
        }

        private LayerDrawable l(X x3, Context context, int i3) {
            BitmapDrawable bitmapDrawable;
            BitmapDrawable bitmapDrawable2;
            BitmapDrawable bitmapDrawable3;
            int dimensionPixelSize = context.getResources().getDimensionPixelSize(i3);
            Drawable drawableI = x3.i(context, d.e.f8838F);
            Drawable drawableI2 = x3.i(context, d.e.f8839G);
            if ((drawableI instanceof BitmapDrawable) && drawableI.getIntrinsicWidth() == dimensionPixelSize && drawableI.getIntrinsicHeight() == dimensionPixelSize) {
                bitmapDrawable = (BitmapDrawable) drawableI;
                bitmapDrawable2 = new BitmapDrawable(bitmapDrawable.getBitmap());
            } else {
                Bitmap bitmapCreateBitmap = Bitmap.createBitmap(dimensionPixelSize, dimensionPixelSize, Bitmap.Config.ARGB_8888);
                Canvas canvas = new Canvas(bitmapCreateBitmap);
                drawableI.setBounds(0, 0, dimensionPixelSize, dimensionPixelSize);
                drawableI.draw(canvas);
                bitmapDrawable = new BitmapDrawable(bitmapCreateBitmap);
                bitmapDrawable2 = new BitmapDrawable(bitmapCreateBitmap);
            }
            bitmapDrawable2.setTileModeX(Shader.TileMode.REPEAT);
            if ((drawableI2 instanceof BitmapDrawable) && drawableI2.getIntrinsicWidth() == dimensionPixelSize && drawableI2.getIntrinsicHeight() == dimensionPixelSize) {
                bitmapDrawable3 = (BitmapDrawable) drawableI2;
            } else {
                Bitmap bitmapCreateBitmap2 = Bitmap.createBitmap(dimensionPixelSize, dimensionPixelSize, Bitmap.Config.ARGB_8888);
                Canvas canvas2 = new Canvas(bitmapCreateBitmap2);
                drawableI2.setBounds(0, 0, dimensionPixelSize, dimensionPixelSize);
                drawableI2.draw(canvas2);
                bitmapDrawable3 = new BitmapDrawable(bitmapCreateBitmap2);
            }
            LayerDrawable layerDrawable = new LayerDrawable(new Drawable[]{bitmapDrawable, bitmapDrawable3, bitmapDrawable2});
            layerDrawable.setId(0, R.id.background);
            layerDrawable.setId(1, R.id.secondaryProgress);
            layerDrawable.setId(2, R.id.progress);
            return layerDrawable;
        }

        private void m(Drawable drawable, int i3, PorterDuff.Mode mode) {
            Drawable drawableMutate = drawable.mutate();
            if (mode == null) {
                mode = C0237k.f4094b;
            }
            drawableMutate.setColorFilter(C0237k.e(i3, mode));
        }

        /* JADX WARN: Removed duplicated region for block: B:22:0x0051  */
        /* JADX WARN: Removed duplicated region for block: B:26:0x0066 A[RETURN] */
        @Override // androidx.appcompat.widget.X.c
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean a(android.content.Context r8, int r9, android.graphics.drawable.Drawable r10) {
            /*
                r7 = this;
                android.graphics.PorterDuff$Mode r0 = androidx.appcompat.widget.C0237k.a()
                int[] r1 = r7.f4097a
                boolean r1 = r7.f(r1, r9)
                r2 = 1
                r3 = 0
                r4 = -1
                if (r1 == 0) goto L15
                int r9 = d.AbstractC0502a.f8809u
            L11:
                r1 = r0
                r5 = r2
            L13:
                r0 = r4
                goto L4f
            L15:
                int[] r1 = r7.f4099c
                boolean r1 = r7.f(r1, r9)
                if (r1 == 0) goto L20
                int r9 = d.AbstractC0502a.f8807s
                goto L11
            L20:
                int[] r1 = r7.f4100d
                boolean r1 = r7.f(r1, r9)
                r5 = 16842801(0x1010031, float:2.3693695E-38)
                if (r1 == 0) goto L32
                android.graphics.PorterDuff$Mode r0 = android.graphics.PorterDuff.Mode.MULTIPLY
            L2d:
                r1 = r0
                r0 = r4
                r9 = r5
                r5 = r2
                goto L4f
            L32:
                int r1 = d.e.f8872u
                if (r9 != r1) goto L46
                r9 = 1109603123(0x42233333, float:40.8)
                int r9 = java.lang.Math.round(r9)
                r1 = 16842800(0x1010030, float:2.3693693E-38)
                r5 = r2
                r6 = r0
                r0 = r9
                r9 = r1
                r1 = r6
                goto L4f
            L46:
                int r1 = d.e.f8863l
                if (r9 != r1) goto L4b
                goto L2d
            L4b:
                r1 = r0
                r9 = r3
                r5 = r9
                goto L13
            L4f:
                if (r5 == 0) goto L66
                android.graphics.drawable.Drawable r10 = r10.mutate()
                int r8 = androidx.appcompat.widget.c0.c(r8, r9)
                android.graphics.PorterDuffColorFilter r8 = androidx.appcompat.widget.C0237k.e(r8, r1)
                r10.setColorFilter(r8)
                if (r0 == r4) goto L65
                r10.setAlpha(r0)
            L65:
                return r2
            L66:
                return r3
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.C0237k.a.a(android.content.Context, int, android.graphics.drawable.Drawable):boolean");
        }

        @Override // androidx.appcompat.widget.X.c
        public PorterDuff.Mode b(int i3) {
            if (i3 == d.e.f8840H) {
                return PorterDuff.Mode.MULTIPLY;
            }
            return null;
        }

        @Override // androidx.appcompat.widget.X.c
        public Drawable c(X x3, Context context, int i3) {
            if (i3 == d.e.f8861j) {
                return new LayerDrawable(new Drawable[]{x3.i(context, d.e.f8860i), x3.i(context, d.e.f8862k)});
            }
            if (i3 == d.e.f8876y) {
                return l(x3, context, d.d.f8826c);
            }
            if (i3 == d.e.f8875x) {
                return l(x3, context, d.d.f8827d);
            }
            if (i3 == d.e.f8877z) {
                return l(x3, context, d.d.f8828e);
            }
            return null;
        }

        @Override // androidx.appcompat.widget.X.c
        public ColorStateList d(Context context, int i3) {
            if (i3 == d.e.f8864m) {
                return AbstractC0510a.a(context, d.c.f8820e);
            }
            if (i3 == d.e.f8841I) {
                return AbstractC0510a.a(context, d.c.f8823h);
            }
            if (i3 == d.e.f8840H) {
                return k(context);
            }
            if (i3 == d.e.f8857f) {
                return j(context);
            }
            if (i3 == d.e.f8853b) {
                return g(context);
            }
            if (i3 == d.e.f8856e) {
                return i(context);
            }
            if (i3 == d.e.f8836D || i3 == d.e.f8837E) {
                return AbstractC0510a.a(context, d.c.f8822g);
            }
            if (f(this.f4098b, i3)) {
                return c0.e(context, AbstractC0502a.f8809u);
            }
            if (f(this.f4101e, i3)) {
                return AbstractC0510a.a(context, d.c.f8819d);
            }
            if (f(this.f4102f, i3)) {
                return AbstractC0510a.a(context, d.c.f8818c);
            }
            if (i3 == d.e.f8833A) {
                return AbstractC0510a.a(context, d.c.f8821f);
            }
            return null;
        }

        @Override // androidx.appcompat.widget.X.c
        public boolean e(Context context, int i3, Drawable drawable) {
            if (i3 == d.e.f8835C) {
                LayerDrawable layerDrawable = (LayerDrawable) drawable;
                m(layerDrawable.findDrawableByLayerId(R.id.background), c0.c(context, AbstractC0502a.f8809u), C0237k.f4094b);
                m(layerDrawable.findDrawableByLayerId(R.id.secondaryProgress), c0.c(context, AbstractC0502a.f8809u), C0237k.f4094b);
                m(layerDrawable.findDrawableByLayerId(R.id.progress), c0.c(context, AbstractC0502a.f8807s), C0237k.f4094b);
                return true;
            }
            if (i3 != d.e.f8876y && i3 != d.e.f8875x && i3 != d.e.f8877z) {
                return false;
            }
            LayerDrawable layerDrawable2 = (LayerDrawable) drawable;
            m(layerDrawable2.findDrawableByLayerId(R.id.background), c0.b(context, AbstractC0502a.f8809u), C0237k.f4094b);
            m(layerDrawable2.findDrawableByLayerId(R.id.secondaryProgress), c0.c(context, AbstractC0502a.f8807s), C0237k.f4094b);
            m(layerDrawable2.findDrawableByLayerId(R.id.progress), c0.c(context, AbstractC0502a.f8807s), C0237k.f4094b);
            return true;
        }
    }

    public static synchronized C0237k b() {
        try {
            if (f4095c == null) {
                h();
            }
        } catch (Throwable th) {
            throw th;
        }
        return f4095c;
    }

    public static synchronized PorterDuffColorFilter e(int i3, PorterDuff.Mode mode) {
        return X.k(i3, mode);
    }

    public static synchronized void h() {
        if (f4095c == null) {
            C0237k c0237k = new C0237k();
            f4095c = c0237k;
            c0237k.f4096a = X.g();
            f4095c.f4096a.t(new a());
        }
    }

    static void i(Drawable drawable, e0 e0Var, int[] iArr) {
        X.v(drawable, e0Var, iArr);
    }

    public synchronized Drawable c(Context context, int i3) {
        return this.f4096a.i(context, i3);
    }

    synchronized Drawable d(Context context, int i3, boolean z3) {
        return this.f4096a.j(context, i3, z3);
    }

    synchronized ColorStateList f(Context context, int i3) {
        return this.f4096a.l(context, i3);
    }

    public synchronized void g(Context context) {
        this.f4096a.r(context);
    }
}
