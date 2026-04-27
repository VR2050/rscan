package w;

import android.content.Context;
import android.util.Log;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.animation.Interpolator;
import android.widget.OverScroller;
import androidx.core.view.V;
import java.util.Arrays;

/* JADX INFO: renamed from: w.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0711c {

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private static final Interpolator f10257w = new a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f10258a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f10259b;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private float[] f10261d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private float[] f10262e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private float[] f10263f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private float[] f10264g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int[] f10265h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int[] f10266i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int[] f10267j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f10268k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private VelocityTracker f10269l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private float f10270m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private float f10271n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private int f10272o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f10273p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private OverScroller f10274q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final AbstractC0153c f10275r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private View f10276s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f10277t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final ViewGroup f10278u;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f10260c = -1;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final Runnable f10279v = new b();

    /* JADX INFO: renamed from: w.c$a */
    static class a implements Interpolator {
        a() {
        }

        @Override // android.animation.TimeInterpolator
        public float getInterpolation(float f3) {
            float f4 = f3 - 1.0f;
            return (f4 * f4 * f4 * f4 * f4) + 1.0f;
        }
    }

    /* JADX INFO: renamed from: w.c$b */
    class b implements Runnable {
        b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            C0711c.this.J(0);
        }
    }

    private C0711c(Context context, ViewGroup viewGroup, AbstractC0153c abstractC0153c) {
        if (viewGroup == null) {
            throw new IllegalArgumentException("Parent view may not be null");
        }
        if (abstractC0153c == null) {
            throw new IllegalArgumentException("Callback may not be null");
        }
        this.f10278u = viewGroup;
        this.f10275r = abstractC0153c;
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        this.f10272o = (int) ((context.getResources().getDisplayMetrics().density * 20.0f) + 0.5f);
        this.f10259b = viewConfiguration.getScaledTouchSlop();
        this.f10270m = viewConfiguration.getScaledMaximumFlingVelocity();
        this.f10271n = viewConfiguration.getScaledMinimumFlingVelocity();
        this.f10274q = new OverScroller(context, f10257w);
    }

    private boolean C(int i3) {
        if (B(i3)) {
            return true;
        }
        Log.e("ViewDragHelper", "Ignoring pointerId=" + i3 + " because ACTION_DOWN was not received for this pointer before ACTION_MOVE. It likely happened because  ViewDragHelper did not receive all the events in the event stream.");
        return false;
    }

    private void F() {
        this.f10269l.computeCurrentVelocity(1000, this.f10270m);
        p(g(this.f10269l.getXVelocity(this.f10260c), this.f10271n, this.f10270m), g(this.f10269l.getYVelocity(this.f10260c), this.f10271n, this.f10270m));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v11 */
    /* JADX WARN: Type inference failed for: r0v12 */
    /* JADX WARN: Type inference failed for: r0v13 */
    /* JADX WARN: Type inference failed for: r0v14 */
    /* JADX WARN: Type inference failed for: r0v15 */
    /* JADX WARN: Type inference failed for: r0v16 */
    /* JADX WARN: Type inference failed for: r0v2 */
    /* JADX WARN: Type inference failed for: r0v3 */
    /* JADX WARN: Type inference failed for: r0v4, types: [int] */
    /* JADX WARN: Type inference failed for: r3v3, types: [w.c$c] */
    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    private void G(float f3, float f4, int i3) {
        boolean zC = c(f3, f4, i3, 1);
        ?? r02 = zC;
        if (c(f4, f3, i3, 4)) {
            r02 = (zC ? 1 : 0) | 4;
        }
        ?? r03 = r02;
        if (c(f3, f4, i3, 2)) {
            r03 = (r02 == true ? 1 : 0) | 2;
        }
        ?? r04 = r03;
        if (c(f4, f3, i3, 8)) {
            r04 = (r03 == true ? 1 : 0) | 8;
        }
        if (r04 != 0) {
            int[] iArr = this.f10266i;
            iArr[i3] = iArr[i3] | r04;
            this.f10275r.f(r04, i3);
        }
    }

    private void H(float f3, float f4, int i3) {
        s(i3);
        float[] fArr = this.f10261d;
        this.f10263f[i3] = f3;
        fArr[i3] = f3;
        float[] fArr2 = this.f10262e;
        this.f10264g[i3] = f4;
        fArr2[i3] = f4;
        this.f10265h[i3] = x((int) f3, (int) f4);
        this.f10268k |= 1 << i3;
    }

    private void I(MotionEvent motionEvent) {
        int pointerCount = motionEvent.getPointerCount();
        for (int i3 = 0; i3 < pointerCount; i3++) {
            int pointerId = motionEvent.getPointerId(i3);
            if (C(pointerId)) {
                float x3 = motionEvent.getX(i3);
                float y3 = motionEvent.getY(i3);
                this.f10263f[pointerId] = x3;
                this.f10264g[pointerId] = y3;
            }
        }
    }

    private boolean c(float f3, float f4, int i3, int i4) {
        float fAbs = Math.abs(f3);
        float fAbs2 = Math.abs(f4);
        if ((this.f10265h[i3] & i4) != i4 || (this.f10273p & i4) == 0 || (this.f10267j[i3] & i4) == i4 || (this.f10266i[i3] & i4) == i4) {
            return false;
        }
        int i5 = this.f10259b;
        if (fAbs <= i5 && fAbs2 <= i5) {
            return false;
        }
        if (fAbs >= fAbs2 * 0.5f || !this.f10275r.g(i4)) {
            return (this.f10266i[i3] & i4) == 0 && fAbs > ((float) this.f10259b);
        }
        int[] iArr = this.f10267j;
        iArr[i3] = iArr[i3] | i4;
        return false;
    }

    private boolean f(View view, float f3, float f4) {
        if (view == null) {
            return false;
        }
        boolean z3 = this.f10275r.d(view) > 0;
        boolean z4 = this.f10275r.e(view) > 0;
        if (!z3 || !z4) {
            return z3 ? Math.abs(f3) > ((float) this.f10259b) : z4 && Math.abs(f4) > ((float) this.f10259b);
        }
        float f5 = (f3 * f3) + (f4 * f4);
        int i3 = this.f10259b;
        return f5 > ((float) (i3 * i3));
    }

    private float g(float f3, float f4, float f5) {
        float fAbs = Math.abs(f3);
        if (fAbs < f4) {
            return 0.0f;
        }
        return fAbs > f5 ? f3 > 0.0f ? f5 : -f5 : f3;
    }

    private int h(int i3, int i4, int i5) {
        int iAbs = Math.abs(i3);
        if (iAbs < i4) {
            return 0;
        }
        return iAbs > i5 ? i3 > 0 ? i5 : -i5 : i3;
    }

    private void i() {
        float[] fArr = this.f10261d;
        if (fArr == null) {
            return;
        }
        Arrays.fill(fArr, 0.0f);
        Arrays.fill(this.f10262e, 0.0f);
        Arrays.fill(this.f10263f, 0.0f);
        Arrays.fill(this.f10264g, 0.0f);
        Arrays.fill(this.f10265h, 0);
        Arrays.fill(this.f10266i, 0);
        Arrays.fill(this.f10267j, 0);
        this.f10268k = 0;
    }

    private void j(int i3) {
        if (this.f10261d == null || !B(i3)) {
            return;
        }
        this.f10261d[i3] = 0.0f;
        this.f10262e[i3] = 0.0f;
        this.f10263f[i3] = 0.0f;
        this.f10264g[i3] = 0.0f;
        this.f10265h[i3] = 0;
        this.f10266i[i3] = 0;
        this.f10267j[i3] = 0;
        this.f10268k = (~(1 << i3)) & this.f10268k;
    }

    private int k(int i3, int i4, int i5) {
        if (i3 == 0) {
            return 0;
        }
        int width = this.f10278u.getWidth();
        float f3 = width / 2;
        float fQ = f3 + (q(Math.min(1.0f, Math.abs(i3) / width)) * f3);
        int iAbs = Math.abs(i4);
        return Math.min(iAbs > 0 ? Math.round(Math.abs(fQ / iAbs) * 1000.0f) * 4 : (int) (((Math.abs(i3) / i5) + 1.0f) * 256.0f), 600);
    }

    private int l(View view, int i3, int i4, int i5, int i6) {
        float f3;
        float f4;
        float f5;
        float f6;
        int iH = h(i5, (int) this.f10271n, (int) this.f10270m);
        int iH2 = h(i6, (int) this.f10271n, (int) this.f10270m);
        int iAbs = Math.abs(i3);
        int iAbs2 = Math.abs(i4);
        int iAbs3 = Math.abs(iH);
        int iAbs4 = Math.abs(iH2);
        int i7 = iAbs3 + iAbs4;
        int i8 = iAbs + iAbs2;
        if (iH != 0) {
            f3 = iAbs3;
            f4 = i7;
        } else {
            f3 = iAbs;
            f4 = i8;
        }
        float f7 = f3 / f4;
        if (iH2 != 0) {
            f5 = iAbs4;
            f6 = i7;
        } else {
            f5 = iAbs2;
            f6 = i8;
        }
        return (int) ((k(i3, iH, this.f10275r.d(view)) * f7) + (k(i4, iH2, this.f10275r.e(view)) * (f5 / f6)));
    }

    public static C0711c n(ViewGroup viewGroup, float f3, AbstractC0153c abstractC0153c) {
        C0711c c0711cO = o(viewGroup, abstractC0153c);
        c0711cO.f10259b = (int) (c0711cO.f10259b * (1.0f / f3));
        return c0711cO;
    }

    public static C0711c o(ViewGroup viewGroup, AbstractC0153c abstractC0153c) {
        return new C0711c(viewGroup.getContext(), viewGroup, abstractC0153c);
    }

    private void p(float f3, float f4) {
        this.f10277t = true;
        this.f10275r.l(this.f10276s, f3, f4);
        this.f10277t = false;
        if (this.f10258a == 1) {
            J(0);
        }
    }

    private float q(float f3) {
        return (float) Math.sin((f3 - 0.5f) * 0.47123894f);
    }

    private void r(int i3, int i4, int i5, int i6) {
        int left = this.f10276s.getLeft();
        int top = this.f10276s.getTop();
        if (i5 != 0) {
            i3 = this.f10275r.a(this.f10276s, i3, i5);
            V.K(this.f10276s, i3 - left);
        }
        int i7 = i3;
        if (i6 != 0) {
            i4 = this.f10275r.b(this.f10276s, i4, i6);
            V.L(this.f10276s, i4 - top);
        }
        int i8 = i4;
        if (i5 == 0 && i6 == 0) {
            return;
        }
        this.f10275r.k(this.f10276s, i7, i8, i7 - left, i8 - top);
    }

    private void s(int i3) {
        float[] fArr = this.f10261d;
        if (fArr == null || fArr.length <= i3) {
            int i4 = i3 + 1;
            float[] fArr2 = new float[i4];
            float[] fArr3 = new float[i4];
            float[] fArr4 = new float[i4];
            float[] fArr5 = new float[i4];
            int[] iArr = new int[i4];
            int[] iArr2 = new int[i4];
            int[] iArr3 = new int[i4];
            if (fArr != null) {
                System.arraycopy(fArr, 0, fArr2, 0, fArr.length);
                float[] fArr6 = this.f10262e;
                System.arraycopy(fArr6, 0, fArr3, 0, fArr6.length);
                float[] fArr7 = this.f10263f;
                System.arraycopy(fArr7, 0, fArr4, 0, fArr7.length);
                float[] fArr8 = this.f10264g;
                System.arraycopy(fArr8, 0, fArr5, 0, fArr8.length);
                int[] iArr4 = this.f10265h;
                System.arraycopy(iArr4, 0, iArr, 0, iArr4.length);
                int[] iArr5 = this.f10266i;
                System.arraycopy(iArr5, 0, iArr2, 0, iArr5.length);
                int[] iArr6 = this.f10267j;
                System.arraycopy(iArr6, 0, iArr3, 0, iArr6.length);
            }
            this.f10261d = fArr2;
            this.f10262e = fArr3;
            this.f10263f = fArr4;
            this.f10264g = fArr5;
            this.f10265h = iArr;
            this.f10266i = iArr2;
            this.f10267j = iArr3;
        }
    }

    private boolean u(int i3, int i4, int i5, int i6) {
        int left = this.f10276s.getLeft();
        int top = this.f10276s.getTop();
        int i7 = i3 - left;
        int i8 = i4 - top;
        if (i7 == 0 && i8 == 0) {
            this.f10274q.abortAnimation();
            J(0);
            return false;
        }
        this.f10274q.startScroll(left, top, i7, i8, l(this.f10276s, i7, i8, i5, i6));
        J(2);
        return true;
    }

    private int x(int i3, int i4) {
        int i5 = i3 < this.f10278u.getLeft() + this.f10272o ? 1 : 0;
        if (i4 < this.f10278u.getTop() + this.f10272o) {
            i5 |= 4;
        }
        if (i3 > this.f10278u.getRight() - this.f10272o) {
            i5 |= 2;
        }
        return i4 > this.f10278u.getBottom() - this.f10272o ? i5 | 8 : i5;
    }

    public boolean A(int i3, int i4) {
        return D(this.f10276s, i3, i4);
    }

    public boolean B(int i3) {
        return ((1 << i3) & this.f10268k) != 0;
    }

    public boolean D(View view, int i3, int i4) {
        return view != null && i3 >= view.getLeft() && i3 < view.getRight() && i4 >= view.getTop() && i4 < view.getBottom();
    }

    public void E(MotionEvent motionEvent) {
        int i3;
        int actionMasked = motionEvent.getActionMasked();
        int actionIndex = motionEvent.getActionIndex();
        if (actionMasked == 0) {
            a();
        }
        if (this.f10269l == null) {
            this.f10269l = VelocityTracker.obtain();
        }
        this.f10269l.addMovement(motionEvent);
        int i4 = 0;
        if (actionMasked == 0) {
            float x3 = motionEvent.getX();
            float y3 = motionEvent.getY();
            int pointerId = motionEvent.getPointerId(0);
            View viewT = t((int) x3, (int) y3);
            H(x3, y3, pointerId);
            P(viewT, pointerId);
            int i5 = this.f10265h[pointerId];
            int i6 = this.f10273p;
            if ((i5 & i6) != 0) {
                this.f10275r.h(i5 & i6, pointerId);
                return;
            }
            return;
        }
        if (actionMasked == 1) {
            if (this.f10258a == 1) {
                F();
            }
            a();
            return;
        }
        if (actionMasked == 2) {
            if (this.f10258a == 1) {
                if (C(this.f10260c)) {
                    int iFindPointerIndex = motionEvent.findPointerIndex(this.f10260c);
                    float x4 = motionEvent.getX(iFindPointerIndex);
                    float y4 = motionEvent.getY(iFindPointerIndex);
                    float[] fArr = this.f10263f;
                    int i7 = this.f10260c;
                    int i8 = (int) (x4 - fArr[i7]);
                    int i9 = (int) (y4 - this.f10264g[i7]);
                    r(this.f10276s.getLeft() + i8, this.f10276s.getTop() + i9, i8, i9);
                    I(motionEvent);
                    return;
                }
                return;
            }
            int pointerCount = motionEvent.getPointerCount();
            while (i4 < pointerCount) {
                int pointerId2 = motionEvent.getPointerId(i4);
                if (C(pointerId2)) {
                    float x5 = motionEvent.getX(i4);
                    float y5 = motionEvent.getY(i4);
                    float f3 = x5 - this.f10261d[pointerId2];
                    float f4 = y5 - this.f10262e[pointerId2];
                    G(f3, f4, pointerId2);
                    if (this.f10258a != 1) {
                        View viewT2 = t((int) x5, (int) y5);
                        if (f(viewT2, f3, f4) && P(viewT2, pointerId2)) {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                i4++;
            }
            I(motionEvent);
            return;
        }
        if (actionMasked == 3) {
            if (this.f10258a == 1) {
                p(0.0f, 0.0f);
            }
            a();
            return;
        }
        if (actionMasked == 5) {
            int pointerId3 = motionEvent.getPointerId(actionIndex);
            float x6 = motionEvent.getX(actionIndex);
            float y6 = motionEvent.getY(actionIndex);
            H(x6, y6, pointerId3);
            if (this.f10258a != 0) {
                if (A((int) x6, (int) y6)) {
                    P(this.f10276s, pointerId3);
                    return;
                }
                return;
            } else {
                P(t((int) x6, (int) y6), pointerId3);
                int i10 = this.f10265h[pointerId3];
                int i11 = this.f10273p;
                if ((i10 & i11) != 0) {
                    this.f10275r.h(i10 & i11, pointerId3);
                    return;
                }
                return;
            }
        }
        if (actionMasked != 6) {
            return;
        }
        int pointerId4 = motionEvent.getPointerId(actionIndex);
        if (this.f10258a == 1 && pointerId4 == this.f10260c) {
            int pointerCount2 = motionEvent.getPointerCount();
            while (true) {
                if (i4 >= pointerCount2) {
                    i3 = -1;
                    break;
                }
                int pointerId5 = motionEvent.getPointerId(i4);
                if (pointerId5 != this.f10260c) {
                    View viewT3 = t((int) motionEvent.getX(i4), (int) motionEvent.getY(i4));
                    View view = this.f10276s;
                    if (viewT3 == view && P(view, pointerId5)) {
                        i3 = this.f10260c;
                        break;
                    }
                }
                i4++;
            }
            if (i3 == -1) {
                F();
            }
        }
        j(pointerId4);
    }

    void J(int i3) {
        this.f10278u.removeCallbacks(this.f10279v);
        if (this.f10258a != i3) {
            this.f10258a = i3;
            this.f10275r.j(i3);
            if (this.f10258a == 0) {
                this.f10276s = null;
            }
        }
    }

    public void K(int i3) {
        this.f10273p = i3;
    }

    public void L(float f3) {
        this.f10271n = f3;
    }

    public boolean M(int i3, int i4) {
        if (this.f10277t) {
            return u(i3, i4, (int) this.f10269l.getXVelocity(this.f10260c), (int) this.f10269l.getYVelocity(this.f10260c));
        }
        throw new IllegalStateException("Cannot settleCapturedViewAt outside of a call to Callback#onViewReleased");
    }

    /* JADX WARN: Removed duplicated region for block: B:54:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00ff  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean N(android.view.MotionEvent r17) {
        /*
            Method dump skipped, instruction units count: 315
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: w.C0711c.N(android.view.MotionEvent):boolean");
    }

    public boolean O(View view, int i3, int i4) {
        this.f10276s = view;
        this.f10260c = -1;
        boolean zU = u(i3, i4, 0, 0);
        if (!zU && this.f10258a == 0 && this.f10276s != null) {
            this.f10276s = null;
        }
        return zU;
    }

    boolean P(View view, int i3) {
        if (view == this.f10276s && this.f10260c == i3) {
            return true;
        }
        if (view == null || !this.f10275r.m(view, i3)) {
            return false;
        }
        this.f10260c = i3;
        b(view, i3);
        return true;
    }

    public void a() {
        this.f10260c = -1;
        i();
        VelocityTracker velocityTracker = this.f10269l;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.f10269l = null;
        }
    }

    public void b(View view, int i3) {
        if (view.getParent() == this.f10278u) {
            this.f10276s = view;
            this.f10260c = i3;
            this.f10275r.i(view, i3);
            J(1);
            return;
        }
        throw new IllegalArgumentException("captureChildView: parameter must be a descendant of the ViewDragHelper's tracked parent view (" + this.f10278u + ")");
    }

    public boolean d(int i3) {
        int length = this.f10261d.length;
        for (int i4 = 0; i4 < length; i4++) {
            if (e(i3, i4)) {
                return true;
            }
        }
        return false;
    }

    public boolean e(int i3, int i4) {
        if (!B(i4)) {
            return false;
        }
        boolean z3 = (i3 & 1) == 1;
        boolean z4 = (i3 & 2) == 2;
        float f3 = this.f10263f[i4] - this.f10261d[i4];
        float f4 = this.f10264g[i4] - this.f10262e[i4];
        if (!z3 || !z4) {
            return z3 ? Math.abs(f3) > ((float) this.f10259b) : z4 && Math.abs(f4) > ((float) this.f10259b);
        }
        float f5 = (f3 * f3) + (f4 * f4);
        int i5 = this.f10259b;
        return f5 > ((float) (i5 * i5));
    }

    public boolean m(boolean z3) {
        if (this.f10258a == 2) {
            boolean zComputeScrollOffset = this.f10274q.computeScrollOffset();
            int currX = this.f10274q.getCurrX();
            int currY = this.f10274q.getCurrY();
            int left = currX - this.f10276s.getLeft();
            int top = currY - this.f10276s.getTop();
            if (left != 0) {
                V.K(this.f10276s, left);
            }
            if (top != 0) {
                V.L(this.f10276s, top);
            }
            if (left != 0 || top != 0) {
                this.f10275r.k(this.f10276s, currX, currY, left, top);
            }
            if (zComputeScrollOffset && currX == this.f10274q.getFinalX() && currY == this.f10274q.getFinalY()) {
                this.f10274q.abortAnimation();
                zComputeScrollOffset = false;
            }
            if (!zComputeScrollOffset) {
                if (z3) {
                    this.f10278u.post(this.f10279v);
                } else {
                    J(0);
                }
            }
        }
        return this.f10258a == 2;
    }

    public View t(int i3, int i4) {
        for (int childCount = this.f10278u.getChildCount() - 1; childCount >= 0; childCount--) {
            View childAt = this.f10278u.getChildAt(this.f10275r.c(childCount));
            if (i3 >= childAt.getLeft() && i3 < childAt.getRight() && i4 >= childAt.getTop() && i4 < childAt.getBottom()) {
                return childAt;
            }
        }
        return null;
    }

    public View v() {
        return this.f10276s;
    }

    public int w() {
        return this.f10272o;
    }

    public int y() {
        return this.f10259b;
    }

    public int z() {
        return this.f10258a;
    }

    /* JADX INFO: renamed from: w.c$c, reason: collision with other inner class name */
    public static abstract class AbstractC0153c {
        public abstract int a(View view, int i3, int i4);

        public abstract int b(View view, int i3, int i4);

        public abstract int d(View view);

        public int e(View view) {
            return 0;
        }

        public abstract void f(int i3, int i4);

        public abstract boolean g(int i3);

        public abstract void h(int i3, int i4);

        public abstract void i(View view, int i3);

        public abstract void j(int i3);

        public abstract void k(View view, int i3, int i4, int i5, int i6);

        public abstract void l(View view, float f3, float f4);

        public abstract boolean m(View view, int i3);

        public int c(int i3) {
            return i3;
        }
    }
}
