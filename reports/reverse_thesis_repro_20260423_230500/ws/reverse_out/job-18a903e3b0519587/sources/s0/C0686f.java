package s0;

import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.SystemClock;
import java.util.Arrays;

/* JADX INFO: renamed from: s0.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0686f extends AbstractC0681a {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final Drawable[] f10010j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final boolean f10011k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final int f10012l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final int f10013m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    int f10014n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    int f10015o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    long f10016p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    int[] f10017q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    int[] f10018r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    int f10019s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    boolean[] f10020t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    int f10021u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private y0.m f10022v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private boolean f10023w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private boolean f10024x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private boolean f10025y;

    public C0686f(Drawable[] drawableArr, boolean z3, int i3) {
        super(drawableArr);
        this.f10025y = true;
        X.k.j(drawableArr.length >= 1, "At least one layer required!");
        this.f10010j = drawableArr;
        this.f10017q = new int[drawableArr.length];
        this.f10018r = new int[drawableArr.length];
        this.f10019s = 255;
        this.f10020t = new boolean[drawableArr.length];
        this.f10021u = 0;
        this.f10011k = z3;
        this.f10012l = z3 ? 255 : 0;
        this.f10013m = i3;
        t();
    }

    private void h(Canvas canvas, Drawable drawable, int i3) {
        if (drawable == null || i3 <= 0) {
            return;
        }
        this.f10021u++;
        if (this.f10025y) {
            drawable.mutate();
        }
        drawable.setAlpha(i3);
        this.f10021u--;
        drawable.draw(canvas);
    }

    private void q() {
        if (this.f10023w) {
            this.f10023w = false;
            y0.m mVar = this.f10022v;
            if (mVar != null) {
                mVar.c();
            }
        }
    }

    private void r() {
        int i3;
        if (!this.f10023w && (i3 = this.f10013m) >= 0) {
            boolean[] zArr = this.f10020t;
            if (i3 < zArr.length && zArr[i3]) {
                this.f10023w = true;
                y0.m mVar = this.f10022v;
                if (mVar != null) {
                    mVar.b();
                }
            }
        }
    }

    private void s() {
        if (this.f10024x && this.f10014n == 2 && this.f10020t[this.f10013m]) {
            y0.m mVar = this.f10022v;
            if (mVar != null) {
                mVar.a();
            }
            this.f10024x = false;
        }
    }

    private void t() {
        this.f10014n = 2;
        Arrays.fill(this.f10017q, this.f10012l);
        this.f10017q[0] = 255;
        Arrays.fill(this.f10018r, this.f10012l);
        this.f10018r[0] = 255;
        Arrays.fill(this.f10020t, this.f10011k);
        this.f10020t[0] = true;
    }

    private boolean v(float f3) {
        boolean z3 = true;
        for (int i3 = 0; i3 < this.f10010j.length; i3++) {
            boolean z4 = this.f10020t[i3];
            int i4 = z4 ? 1 : -1;
            int[] iArr = this.f10018r;
            int i5 = (int) (this.f10017q[i3] + (i4 * 255 * f3));
            iArr[i3] = i5;
            if (i5 < 0) {
                iArr[i3] = 0;
            }
            if (iArr[i3] > 255) {
                iArr[i3] = 255;
            }
            if (z4 && iArr[i3] < 255) {
                z3 = false;
            }
            if (!z4 && iArr[i3] > 0) {
                z3 = false;
            }
        }
        return z3;
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0057 A[LOOP:0: B:25:0x0052->B:27:0x0057, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0072 A[EDGE_INSN: B:32:0x0072->B:28:0x0072 BREAK  A[LOOP:0: B:25:0x0052->B:27:0x0057], SYNTHETIC] */
    @Override // android.graphics.drawable.Drawable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void draw(android.graphics.Canvas r9) {
        /*
            r8 = this;
            int r0 = r8.f10014n
            r1 = 2
            r2 = 0
            r3 = 1
            if (r0 == 0) goto L2c
            if (r0 == r3) goto La
            goto L52
        La:
            int r0 = r8.f10015o
            if (r0 <= 0) goto L10
            r0 = r3
            goto L11
        L10:
            r0 = r2
        L11:
            X.k.i(r0)
            long r4 = r8.p()
            long r6 = r8.f10016p
            long r4 = r4 - r6
            float r0 = (float) r4
            int r4 = r8.f10015o
            float r4 = (float) r4
            float r0 = r0 / r4
            boolean r0 = r8.v(r0)
            if (r0 == 0) goto L27
            goto L28
        L27:
            r1 = r3
        L28:
            r8.f10014n = r1
        L2a:
            r3 = r0
            goto L52
        L2c:
            int[] r0 = r8.f10018r
            int[] r4 = r8.f10017q
            android.graphics.drawable.Drawable[] r5 = r8.f10010j
            int r5 = r5.length
            java.lang.System.arraycopy(r0, r2, r4, r2, r5)
            long r4 = r8.p()
            r8.f10016p = r4
            int r0 = r8.f10015o
            if (r0 != 0) goto L43
            r0 = 1065353216(0x3f800000, float:1.0)
            goto L44
        L43:
            r0 = 0
        L44:
            boolean r0 = r8.v(r0)
            r8.r()
            if (r0 == 0) goto L4e
            goto L4f
        L4e:
            r1 = r3
        L4f:
            r8.f10014n = r1
            goto L2a
        L52:
            android.graphics.drawable.Drawable[] r0 = r8.f10010j
            int r1 = r0.length
            if (r2 >= r1) goto L72
            r0 = r0[r2]
            int[] r1 = r8.f10018r
            r1 = r1[r2]
            int r4 = r8.f10019s
            int r1 = r1 * r4
            double r4 = (double) r1
            r6 = 4643176031446892544(0x406fe00000000000, double:255.0)
            double r4 = r4 / r6
            double r4 = java.lang.Math.ceil(r4)
            int r1 = (int) r4
            r8.h(r9, r0, r1)
            int r2 = r2 + 1
            goto L52
        L72:
            if (r3 == 0) goto L7b
            r8.q()
            r8.s()
            goto L7e
        L7b:
            r8.invalidateSelf()
        L7e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: s0.C0686f.draw(android.graphics.Canvas):void");
    }

    public void g() {
        this.f10021u++;
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.f10019s;
    }

    @Override // android.graphics.drawable.Drawable
    public void invalidateSelf() {
        if (this.f10021u == 0) {
            super.invalidateSelf();
        }
    }

    public void j() {
        this.f10021u--;
        invalidateSelf();
    }

    public void k() {
        this.f10014n = 0;
        Arrays.fill(this.f10020t, true);
        invalidateSelf();
    }

    public void l(int i3) {
        this.f10014n = 0;
        this.f10020t[i3] = true;
        invalidateSelf();
    }

    public void m(int i3) {
        this.f10014n = 0;
        this.f10020t[i3] = false;
        invalidateSelf();
    }

    public void o() {
        this.f10014n = 2;
        for (int i3 = 0; i3 < this.f10010j.length; i3++) {
            this.f10018r[i3] = this.f10020t[i3] ? 255 : 0;
        }
        invalidateSelf();
    }

    protected long p() {
        return SystemClock.uptimeMillis();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        if (this.f10019s != i3) {
            this.f10019s = i3;
            invalidateSelf();
        }
    }

    public void u(int i3) {
        this.f10015o = i3;
        if (this.f10014n == 1) {
            this.f10014n = 0;
        }
    }
}
