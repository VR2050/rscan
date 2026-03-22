package p005b.p190k.p191a.p192a;

import android.content.Context;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.animation.Interpolator;
import android.widget.Scroller;
import com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout;
import java.util.Arrays;
import java.util.Objects;

/* renamed from: b.k.a.a.d */
/* loaded from: classes.dex */
public class C1883d {

    /* renamed from: a */
    public static final Interpolator f2917a = new a();

    /* renamed from: b */
    public int f2918b;

    /* renamed from: c */
    public int f2919c;

    /* renamed from: e */
    public float[] f2921e;

    /* renamed from: f */
    public float[] f2922f;

    /* renamed from: g */
    public float[] f2923g;

    /* renamed from: h */
    public float[] f2924h;

    /* renamed from: i */
    public int[] f2925i;

    /* renamed from: j */
    public int[] f2926j;

    /* renamed from: k */
    public int[] f2927k;

    /* renamed from: l */
    public int f2928l;

    /* renamed from: m */
    public VelocityTracker f2929m;

    /* renamed from: n */
    public float f2930n;

    /* renamed from: o */
    public float f2931o;

    /* renamed from: p */
    public int f2932p;

    /* renamed from: q */
    public int f2933q;

    /* renamed from: r */
    public int f2934r;

    /* renamed from: s */
    public Scroller f2935s;

    /* renamed from: t */
    public final c f2936t;

    /* renamed from: u */
    public View f2937u;

    /* renamed from: v */
    public boolean f2938v;

    /* renamed from: w */
    public final ViewGroup f2939w;

    /* renamed from: d */
    public int f2920d = -1;

    /* renamed from: x */
    public final Runnable f2940x = new b();

    /* renamed from: b.k.a.a.d$a */
    public static class a implements Interpolator {
        @Override // android.animation.TimeInterpolator
        public float getInterpolation(float f2) {
            float f3 = f2 - 1.0f;
            return (f3 * f3 * f3 * f3 * f3) + 1.0f;
        }
    }

    /* renamed from: b.k.a.a.d$b */
    public class b implements Runnable {
        public b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            C1883d.this.m1229o(0);
        }
    }

    /* renamed from: b.k.a.a.d$c */
    public static abstract class c {
        /* renamed from: a */
        public abstract void mo1232a(View view, int i2, int i3, int i4, int i5);
    }

    public C1883d(Context context, ViewGroup viewGroup, c cVar) {
        if (cVar == null) {
            throw new IllegalArgumentException("Callback may not be null");
        }
        this.f2939w = viewGroup;
        this.f2936t = cVar;
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        int i2 = (int) ((context.getResources().getDisplayMetrics().density * 20.0f) + 0.5f);
        this.f2932p = i2;
        this.f2933q = i2;
        this.f2919c = viewConfiguration.getScaledTouchSlop();
        this.f2930n = viewConfiguration.getScaledMaximumFlingVelocity();
        this.f2931o = viewConfiguration.getScaledMinimumFlingVelocity();
        this.f2935s = new Scroller(context, f2917a);
    }

    /* renamed from: a */
    public void m1215a() {
        this.f2920d = -1;
        float[] fArr = this.f2921e;
        if (fArr != null) {
            Arrays.fill(fArr, 0.0f);
            Arrays.fill(this.f2922f, 0.0f);
            Arrays.fill(this.f2923g, 0.0f);
            Arrays.fill(this.f2924h, 0.0f);
            Arrays.fill(this.f2925i, 0);
            Arrays.fill(this.f2926j, 0);
            Arrays.fill(this.f2927k, 0);
            this.f2928l = 0;
        }
        VelocityTracker velocityTracker = this.f2929m;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.f2929m = null;
        }
    }

    /* renamed from: b */
    public final boolean m1216b(float f2, float f3, int i2, int i3) {
        float abs = Math.abs(f2);
        float abs2 = Math.abs(f3);
        if ((this.f2925i[i2] & i3) != i3 || (this.f2934r & i3) == 0 || (this.f2927k[i2] & i3) == i3 || (this.f2926j[i2] & i3) == i3) {
            return false;
        }
        int i4 = this.f2919c;
        if (abs <= i4 && abs2 <= i4) {
            return false;
        }
        if (abs < abs2 * 0.5f) {
            Objects.requireNonNull(this.f2936t);
        }
        return (this.f2926j[i2] & i3) == 0 && abs > ((float) this.f2919c);
    }

    /* renamed from: c */
    public boolean m1217c(int i2, int i3) {
        if (!((this.f2928l & (1 << i3)) != 0)) {
            return false;
        }
        boolean z = (i2 & 1) == 1;
        boolean z2 = (i2 & 2) == 2;
        float f2 = this.f2923g[i3] - this.f2921e[i3];
        float f3 = this.f2924h[i3] - this.f2922f[i3];
        if (!z || !z2) {
            return z ? Math.abs(f2) > ((float) this.f2919c) : z2 && Math.abs(f3) > ((float) this.f2919c);
        }
        float f4 = (f3 * f3) + (f2 * f2);
        int i4 = this.f2919c;
        return f4 > ((float) (i4 * i4));
    }

    /* renamed from: d */
    public final boolean m1218d(View view, float f2, float f3) {
        if (view == null) {
            return false;
        }
        int i2 = ParallaxBackLayout.this.f9205u;
        boolean z = (i2 & 3) > 0;
        boolean z2 = (i2 & 12) > 0;
        if (!z || !z2) {
            return z ? Math.abs(f2) > ((float) this.f2919c) : z2 && Math.abs(f3) > ((float) this.f2919c);
        }
        float f4 = (f3 * f3) + (f2 * f2);
        int i3 = this.f2919c;
        return f4 > ((float) (i3 * i3));
    }

    /* renamed from: e */
    public final float m1219e(float f2, float f3, float f4) {
        float abs = Math.abs(f2);
        if (abs < f3) {
            return 0.0f;
        }
        return abs > f4 ? f2 > 0.0f ? f4 : -f4 : f2;
    }

    /* renamed from: f */
    public final int m1220f(int i2, int i3, int i4) {
        int abs = Math.abs(i2);
        if (abs < i3) {
            return 0;
        }
        return abs > i4 ? i2 > 0 ? i4 : -i4 : i2;
    }

    /* renamed from: g */
    public final void m1221g(int i2) {
        float[] fArr = this.f2921e;
        if (fArr == null) {
            return;
        }
        fArr[i2] = 0.0f;
        this.f2922f[i2] = 0.0f;
        this.f2923g[i2] = 0.0f;
        this.f2924h[i2] = 0.0f;
        this.f2925i[i2] = 0;
        this.f2926j[i2] = 0;
        this.f2927k[i2] = 0;
        this.f2928l = (~(1 << i2)) & this.f2928l;
    }

    /* renamed from: h */
    public final int m1222h(int i2, int i3, int i4) {
        if (i2 == 0) {
            return 0;
        }
        float width = this.f2939w.getWidth() / 2;
        float sin = (((float) Math.sin((float) ((Math.min(1.0f, Math.abs(i2) / r0) - 0.5f) * 0.4712389167638204d))) * width) + width;
        int abs = Math.abs(i3);
        return Math.min(abs > 0 ? Math.round(Math.abs(sin / abs) * 1000.0f) * 4 : (int) (((Math.abs(i2) / i4) + 1.0f) * 256.0f), 600);
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x017e  */
    /* renamed from: i */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1223i(float r18, float r19) {
        /*
            Method dump skipped, instructions count: 390
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p190k.p191a.p192a.C1883d.m1223i(float, float):void");
    }

    /* renamed from: j */
    public View m1224j(int i2, int i3) {
        for (int childCount = this.f2939w.getChildCount() - 1; childCount >= 0; childCount--) {
            ViewGroup viewGroup = this.f2939w;
            Objects.requireNonNull(this.f2936t);
            View childAt = viewGroup.getChildAt(childCount);
            if (i2 >= childAt.getLeft() && i2 < childAt.getRight() && i3 >= childAt.getTop() && i3 < childAt.getBottom()) {
                return childAt;
            }
        }
        return null;
    }

    /* renamed from: k */
    public final void m1225k() {
        this.f2929m.computeCurrentVelocity(1000, this.f2930n);
        m1223i(m1219e(this.f2929m.getXVelocity(this.f2920d), this.f2931o, this.f2930n), m1219e(this.f2929m.getYVelocity(this.f2920d), this.f2931o, this.f2930n));
    }

    /* renamed from: l */
    public final void m1226l(float f2, float f3, int i2) {
        int i3 = m1216b(f2, f3, i2, 1) ? 1 : 0;
        if (m1216b(f3, f2, i2, 4)) {
            i3 |= 4;
        }
        if (m1216b(f2, f3, i2, 2)) {
            i3 |= 2;
        }
        if (m1216b(f3, f2, i2, 8)) {
            i3 |= 8;
        }
        if (i3 != 0) {
            int[] iArr = this.f2926j;
            iArr[i2] = iArr[i2] | i3;
            Objects.requireNonNull(this.f2936t);
        }
    }

    /* renamed from: m */
    public final void m1227m(float f2, float f3, int i2) {
        float[] fArr = this.f2921e;
        if (fArr == null || fArr.length <= i2) {
            int i3 = i2 + 1;
            float[] fArr2 = new float[i3];
            float[] fArr3 = new float[i3];
            float[] fArr4 = new float[i3];
            float[] fArr5 = new float[i3];
            int[] iArr = new int[i3];
            int[] iArr2 = new int[i3];
            int[] iArr3 = new int[i3];
            if (fArr != null) {
                System.arraycopy(fArr, 0, fArr2, 0, fArr.length);
                float[] fArr6 = this.f2922f;
                System.arraycopy(fArr6, 0, fArr3, 0, fArr6.length);
                float[] fArr7 = this.f2923g;
                System.arraycopy(fArr7, 0, fArr4, 0, fArr7.length);
                float[] fArr8 = this.f2924h;
                System.arraycopy(fArr8, 0, fArr5, 0, fArr8.length);
                int[] iArr4 = this.f2925i;
                System.arraycopy(iArr4, 0, iArr, 0, iArr4.length);
                int[] iArr5 = this.f2926j;
                System.arraycopy(iArr5, 0, iArr2, 0, iArr5.length);
                int[] iArr6 = this.f2927k;
                System.arraycopy(iArr6, 0, iArr3, 0, iArr6.length);
            }
            this.f2921e = fArr2;
            this.f2922f = fArr3;
            this.f2923g = fArr4;
            this.f2924h = fArr5;
            this.f2925i = iArr;
            this.f2926j = iArr2;
            this.f2927k = iArr3;
        }
        float[] fArr9 = this.f2921e;
        this.f2923g[i2] = f2;
        fArr9[i2] = f2;
        float[] fArr10 = this.f2922f;
        this.f2924h[i2] = f3;
        fArr10[i2] = f3;
        int[] iArr7 = this.f2925i;
        int i4 = (int) f2;
        int i5 = (int) f3;
        int i6 = i4 < this.f2939w.getLeft() + this.f2932p ? 1 : 0;
        if (i5 < this.f2939w.getTop() + this.f2932p) {
            i6 |= 4;
        }
        if (i4 > this.f2939w.getRight() - this.f2932p) {
            i6 |= 2;
        }
        if (i5 > this.f2939w.getBottom() - this.f2932p) {
            i6 |= 8;
        }
        iArr7[i2] = i6;
        this.f2928l |= 1 << i2;
    }

    /* renamed from: n */
    public final void m1228n(MotionEvent motionEvent) {
        int pointerCount = motionEvent.getPointerCount();
        for (int i2 = 0; i2 < pointerCount; i2++) {
            int pointerId = motionEvent.getPointerId(i2);
            float x = motionEvent.getX(i2);
            float y = motionEvent.getY(i2);
            this.f2923g[pointerId] = x;
            this.f2924h[pointerId] = y;
        }
    }

    /* renamed from: o */
    public void m1229o(int i2) {
        if (this.f2918b != i2) {
            this.f2918b = i2;
            ParallaxBackLayout.InterfaceC3255c interfaceC3255c = ParallaxBackLayout.this.f9194j;
            if (interfaceC3255c != null) {
                interfaceC3255c.m4020b(i2);
            }
            if (i2 == 0) {
                this.f2937u = null;
            }
        }
    }

    /* renamed from: p */
    public boolean m1230p(MotionEvent motionEvent) {
        View m1224j;
        View m1224j2;
        int actionMasked = motionEvent.getActionMasked();
        int actionIndex = motionEvent.getActionIndex();
        if (actionMasked == 0) {
            m1215a();
        }
        if (this.f2929m == null) {
            this.f2929m = VelocityTracker.obtain();
        }
        this.f2929m.addMovement(motionEvent);
        if (actionMasked != 0) {
            if (actionMasked != 1) {
                if (actionMasked == 2) {
                    int pointerCount = motionEvent.getPointerCount();
                    for (int i2 = 0; i2 < pointerCount; i2++) {
                        int pointerId = motionEvent.getPointerId(i2);
                        float x = motionEvent.getX(i2);
                        float y = motionEvent.getY(i2);
                        float f2 = x - this.f2921e[pointerId];
                        float f3 = y - this.f2922f[pointerId];
                        m1226l(f2, f3, pointerId);
                        if (this.f2918b == 1 || ((m1224j = m1224j((int) x, (int) y)) != null && m1218d(m1224j, f2, f3) && m1231q(m1224j, pointerId))) {
                            break;
                        }
                    }
                    m1228n(motionEvent);
                } else if (actionMasked != 3) {
                    if (actionMasked == 5) {
                        int pointerId2 = motionEvent.getPointerId(actionIndex);
                        float x2 = motionEvent.getX(actionIndex);
                        float y2 = motionEvent.getY(actionIndex);
                        m1227m(x2, y2, pointerId2);
                        int i3 = this.f2918b;
                        if (i3 == 0) {
                            if ((this.f2925i[pointerId2] & this.f2934r) != 0) {
                                Objects.requireNonNull(this.f2936t);
                            }
                        } else if (i3 == 2 && (m1224j2 = m1224j((int) x2, (int) y2)) == this.f2937u) {
                            m1231q(m1224j2, pointerId2);
                        }
                    } else if (actionMasked == 6) {
                        m1221g(motionEvent.getPointerId(actionIndex));
                    }
                }
            }
            m1215a();
        } else {
            float x3 = motionEvent.getX();
            float y3 = motionEvent.getY();
            int pointerId3 = motionEvent.getPointerId(0);
            m1227m(x3, y3, pointerId3);
            View m1224j3 = m1224j((int) x3, (int) y3);
            if (m1224j3 == this.f2937u && this.f2918b == 2) {
                m1231q(m1224j3, pointerId3);
            }
            if ((this.f2925i[pointerId3] & this.f2934r) != 0) {
                Objects.requireNonNull(this.f2936t);
            }
        }
        return this.f2918b == 1;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x004e  */
    /* renamed from: q */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean m1231q(android.view.View r8, int r9) {
        /*
            r7 = this;
            android.view.View r0 = r7.f2937u
            r1 = 1
            if (r8 != r0) goto La
            int r0 = r7.f2920d
            if (r0 != r9) goto La
            return r1
        La:
            r0 = 0
            if (r8 == 0) goto L7f
            b.k.a.a.d$c r2 = r7.f2936t
            com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout$d r2 = (com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout.C3256d) r2
            com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout r2 = com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout.this
            b.k.a.a.d r3 = r2.f9193i
            int r4 = r2.f9205u
            int r5 = r3.f2928l
            int r6 = r1 << r9
            r5 = r5 & r6
            if (r5 == 0) goto L20
            r5 = 1
            goto L21
        L20:
            r5 = 0
        L21:
            if (r5 == 0) goto L2c
            int[] r5 = r3.f2925i
            r5 = r5[r9]
            r5 = r5 & r4
            if (r5 == 0) goto L2c
            r5 = 1
            goto L2d
        L2c:
            r5 = 0
        L2d:
            if (r5 == 0) goto L31
            r2.f9203s = r4
        L31:
            r2 = 2
            if (r4 == r1) goto L46
            if (r4 != r2) goto L37
            goto L46
        L37:
            r2 = 8
            if (r4 == r2) goto L41
            r2 = 4
            if (r4 != r2) goto L3f
            goto L41
        L3f:
            r2 = 0
            goto L4b
        L41:
            boolean r2 = r3.m1217c(r1, r9)
            goto L4a
        L46:
            boolean r2 = r3.m1217c(r2, r9)
        L4a:
            r2 = r2 ^ r1
        L4b:
            r2 = r2 & r5
            if (r2 == 0) goto L7f
            r7.f2920d = r9
            android.view.ViewParent r0 = r8.getParent()
            android.view.ViewGroup r2 = r7.f2939w
            if (r0 != r2) goto L65
            r7.f2937u = r8
            r7.f2920d = r9
            b.k.a.a.d$c r8 = r7.f2936t
            java.util.Objects.requireNonNull(r8)
            r7.m1229o(r1)
            return r1
        L65:
            java.lang.IllegalArgumentException r8 = new java.lang.IllegalArgumentException
            java.lang.String r9 = "captureChildView: parameter must be a descendant of the ViewDragHelper's tracked parent view ("
            java.lang.StringBuilder r9 = p005b.p131d.p132a.p133a.C1499a.m586H(r9)
            android.view.ViewGroup r0 = r7.f2939w
            r9.append(r0)
            java.lang.String r0 = ")"
            r9.append(r0)
            java.lang.String r9 = r9.toString()
            r8.<init>(r9)
            throw r8
        L7f:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p190k.p191a.p192a.C1883d.m1231q(android.view.View, int):boolean");
    }
}
