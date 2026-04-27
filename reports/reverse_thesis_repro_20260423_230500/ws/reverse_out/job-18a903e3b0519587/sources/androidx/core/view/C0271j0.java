package androidx.core.view;

import android.graphics.Rect;
import android.os.Build;
import android.util.Log;
import android.view.View;
import android.view.WindowInsets;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Objects;

/* JADX INFO: renamed from: androidx.core.view.j0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0271j0 {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final C0271j0 f4470b;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final l f4471a;

    /* JADX INFO: renamed from: androidx.core.view.j0$a */
    static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private static Field f4472a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private static Field f4473b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private static Field f4474c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private static boolean f4475d;

        static {
            try {
                Field declaredField = View.class.getDeclaredField("mAttachInfo");
                f4472a = declaredField;
                declaredField.setAccessible(true);
                Class<?> cls = Class.forName("android.view.View$AttachInfo");
                Field declaredField2 = cls.getDeclaredField("mStableInsets");
                f4473b = declaredField2;
                declaredField2.setAccessible(true);
                Field declaredField3 = cls.getDeclaredField("mContentInsets");
                f4474c = declaredField3;
                declaredField3.setAccessible(true);
                f4475d = true;
            } catch (ReflectiveOperationException e3) {
                Log.w("WindowInsetsCompat", "Failed to get visible insets from AttachInfo " + e3.getMessage(), e3);
            }
        }

        public static C0271j0 a(View view) {
            if (f4475d && view.isAttachedToWindow()) {
                try {
                    Object obj = f4472a.get(view.getRootView());
                    if (obj != null) {
                        Rect rect = (Rect) f4473b.get(obj);
                        Rect rect2 = (Rect) f4474c.get(obj);
                        if (rect != null && rect2 != null) {
                            C0271j0 c0271j0A = new b().b(androidx.core.graphics.b.c(rect)).c(androidx.core.graphics.b.c(rect2)).a();
                            c0271j0A.s(c0271j0A);
                            c0271j0A.d(view.getRootView());
                            return c0271j0A;
                        }
                    }
                } catch (IllegalAccessException e3) {
                    Log.w("WindowInsetsCompat", "Failed to get insets from AttachInfo. " + e3.getMessage(), e3);
                }
            }
            return null;
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$e */
    private static class e extends d {
        e() {
        }

        e(C0271j0 c0271j0) {
            super(c0271j0);
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$f */
    private static class f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final C0271j0 f4484a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        androidx.core.graphics.b[] f4485b;

        f() {
            this(new C0271j0((C0271j0) null));
        }

        protected final void a() {
            androidx.core.graphics.b[] bVarArr = this.f4485b;
            if (bVarArr != null) {
                androidx.core.graphics.b bVarF = bVarArr[m.b(1)];
                androidx.core.graphics.b bVarF2 = this.f4485b[m.b(2)];
                if (bVarF2 == null) {
                    bVarF2 = this.f4484a.f(2);
                }
                if (bVarF == null) {
                    bVarF = this.f4484a.f(1);
                }
                f(androidx.core.graphics.b.a(bVarF, bVarF2));
                androidx.core.graphics.b bVar = this.f4485b[m.b(16)];
                if (bVar != null) {
                    e(bVar);
                }
                androidx.core.graphics.b bVar2 = this.f4485b[m.b(32)];
                if (bVar2 != null) {
                    c(bVar2);
                }
                androidx.core.graphics.b bVar3 = this.f4485b[m.b(64)];
                if (bVar3 != null) {
                    g(bVar3);
                }
            }
        }

        abstract C0271j0 b();

        void c(androidx.core.graphics.b bVar) {
        }

        abstract void d(androidx.core.graphics.b bVar);

        void e(androidx.core.graphics.b bVar) {
        }

        abstract void f(androidx.core.graphics.b bVar);

        void g(androidx.core.graphics.b bVar) {
        }

        f(C0271j0 c0271j0) {
            this.f4484a = c0271j0;
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$i */
    private static class i extends h {
        i(C0271j0 c0271j0, WindowInsets windowInsets) {
            super(c0271j0, windowInsets);
        }

        @Override // androidx.core.view.C0271j0.l
        C0271j0 a() {
            return C0271j0.v(this.f4491c.consumeDisplayCutout());
        }

        @Override // androidx.core.view.C0271j0.g, androidx.core.view.C0271j0.l
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof i)) {
                return false;
            }
            i iVar = (i) obj;
            return Objects.equals(this.f4491c, iVar.f4491c) && Objects.equals(this.f4495g, iVar.f4495g);
        }

        @Override // androidx.core.view.C0271j0.l
        r f() {
            return r.e(this.f4491c.getDisplayCutout());
        }

        @Override // androidx.core.view.C0271j0.l
        public int hashCode() {
            return this.f4491c.hashCode();
        }

        i(C0271j0 c0271j0, i iVar) {
            super(c0271j0, iVar);
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$k */
    private static class k extends j {

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        static final C0271j0 f4500q = C0271j0.v(WindowInsets.CONSUMED);

        k(C0271j0 c0271j0, WindowInsets windowInsets) {
            super(c0271j0, windowInsets);
        }

        @Override // androidx.core.view.C0271j0.g, androidx.core.view.C0271j0.l
        final void d(View view) {
        }

        @Override // androidx.core.view.C0271j0.g, androidx.core.view.C0271j0.l
        public androidx.core.graphics.b g(int i3) {
            return androidx.core.graphics.b.d(this.f4491c.getInsets(n.a(i3)));
        }

        @Override // androidx.core.view.C0271j0.g, androidx.core.view.C0271j0.l
        public boolean p(int i3) {
            return this.f4491c.isVisible(n.a(i3));
        }

        k(C0271j0 c0271j0, k kVar) {
            super(c0271j0, kVar);
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$l */
    private static class l {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        static final C0271j0 f4501b = new b().a().a().b().c();

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final C0271j0 f4502a;

        l(C0271j0 c0271j0) {
            this.f4502a = c0271j0;
        }

        C0271j0 a() {
            return this.f4502a;
        }

        C0271j0 b() {
            return this.f4502a;
        }

        C0271j0 c() {
            return this.f4502a;
        }

        void d(View view) {
        }

        void e(C0271j0 c0271j0) {
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof l)) {
                return false;
            }
            l lVar = (l) obj;
            return o() == lVar.o() && n() == lVar.n() && q.c.a(k(), lVar.k()) && q.c.a(i(), lVar.i()) && q.c.a(f(), lVar.f());
        }

        r f() {
            return null;
        }

        androidx.core.graphics.b g(int i3) {
            return androidx.core.graphics.b.f4320e;
        }

        androidx.core.graphics.b h() {
            return k();
        }

        public int hashCode() {
            return q.c.b(Boolean.valueOf(o()), Boolean.valueOf(n()), k(), i(), f());
        }

        androidx.core.graphics.b i() {
            return androidx.core.graphics.b.f4320e;
        }

        androidx.core.graphics.b j() {
            return k();
        }

        androidx.core.graphics.b k() {
            return androidx.core.graphics.b.f4320e;
        }

        androidx.core.graphics.b l() {
            return k();
        }

        C0271j0 m(int i3, int i4, int i5, int i6) {
            return f4501b;
        }

        boolean n() {
            return false;
        }

        boolean o() {
            return false;
        }

        boolean p(int i3) {
            return true;
        }

        public void q(androidx.core.graphics.b[] bVarArr) {
        }

        void r(androidx.core.graphics.b bVar) {
        }

        void s(C0271j0 c0271j0) {
        }

        public void t(androidx.core.graphics.b bVar) {
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$m */
    public static final class m {
        public static int a() {
            return 128;
        }

        static int b(int i3) {
            if (i3 == 1) {
                return 0;
            }
            if (i3 == 2) {
                return 1;
            }
            if (i3 == 4) {
                return 2;
            }
            if (i3 == 8) {
                return 3;
            }
            if (i3 == 16) {
                return 4;
            }
            if (i3 == 32) {
                return 5;
            }
            if (i3 == 64) {
                return 6;
            }
            if (i3 == 128) {
                return 7;
            }
            if (i3 == 256) {
                return 8;
            }
            throw new IllegalArgumentException("type needs to be >= FIRST and <= LAST, type=" + i3);
        }

        public static int c() {
            return 2;
        }

        public static int d() {
            return 1;
        }

        public static int e() {
            return 7;
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$n */
    private static final class n {
        static int a(int i3) {
            int iStatusBars;
            int i4 = 0;
            for (int i5 = 1; i5 <= 256; i5 <<= 1) {
                if ((i3 & i5) != 0) {
                    if (i5 == 1) {
                        iStatusBars = WindowInsets.Type.statusBars();
                    } else if (i5 == 2) {
                        iStatusBars = WindowInsets.Type.navigationBars();
                    } else if (i5 == 4) {
                        iStatusBars = WindowInsets.Type.captionBar();
                    } else if (i5 == 8) {
                        iStatusBars = WindowInsets.Type.ime();
                    } else if (i5 == 16) {
                        iStatusBars = WindowInsets.Type.systemGestures();
                    } else if (i5 == 32) {
                        iStatusBars = WindowInsets.Type.mandatorySystemGestures();
                    } else if (i5 == 64) {
                        iStatusBars = WindowInsets.Type.tappableElement();
                    } else if (i5 == 128) {
                        iStatusBars = WindowInsets.Type.displayCutout();
                    }
                    i4 |= iStatusBars;
                }
            }
            return i4;
        }
    }

    static {
        if (Build.VERSION.SDK_INT >= 30) {
            f4470b = k.f4500q;
        } else {
            f4470b = l.f4501b;
        }
    }

    private C0271j0(WindowInsets windowInsets) {
        int i3 = Build.VERSION.SDK_INT;
        if (i3 >= 30) {
            this.f4471a = new k(this, windowInsets);
            return;
        }
        if (i3 >= 29) {
            this.f4471a = new j(this, windowInsets);
        } else if (i3 >= 28) {
            this.f4471a = new i(this, windowInsets);
        } else {
            this.f4471a = new h(this, windowInsets);
        }
    }

    static androidx.core.graphics.b m(androidx.core.graphics.b bVar, int i3, int i4, int i5, int i6) {
        int iMax = Math.max(0, bVar.f4321a - i3);
        int iMax2 = Math.max(0, bVar.f4322b - i4);
        int iMax3 = Math.max(0, bVar.f4323c - i5);
        int iMax4 = Math.max(0, bVar.f4324d - i6);
        return (iMax == i3 && iMax2 == i4 && iMax3 == i5 && iMax4 == i6) ? bVar : androidx.core.graphics.b.b(iMax, iMax2, iMax3, iMax4);
    }

    public static C0271j0 v(WindowInsets windowInsets) {
        return w(windowInsets, null);
    }

    public static C0271j0 w(WindowInsets windowInsets, View view) {
        C0271j0 c0271j0 = new C0271j0((WindowInsets) q.g.f(windowInsets));
        if (view != null && view.isAttachedToWindow()) {
            c0271j0.s(V.y(view));
            c0271j0.d(view.getRootView());
        }
        return c0271j0;
    }

    public C0271j0 a() {
        return this.f4471a.a();
    }

    public C0271j0 b() {
        return this.f4471a.b();
    }

    public C0271j0 c() {
        return this.f4471a.c();
    }

    void d(View view) {
        this.f4471a.d(view);
    }

    public r e() {
        return this.f4471a.f();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C0271j0) {
            return q.c.a(this.f4471a, ((C0271j0) obj).f4471a);
        }
        return false;
    }

    public androidx.core.graphics.b f(int i3) {
        return this.f4471a.g(i3);
    }

    public androidx.core.graphics.b g() {
        return this.f4471a.i();
    }

    public int h() {
        return this.f4471a.k().f4324d;
    }

    public int hashCode() {
        l lVar = this.f4471a;
        if (lVar == null) {
            return 0;
        }
        return lVar.hashCode();
    }

    public int i() {
        return this.f4471a.k().f4321a;
    }

    public int j() {
        return this.f4471a.k().f4323c;
    }

    public int k() {
        return this.f4471a.k().f4322b;
    }

    public C0271j0 l(int i3, int i4, int i5, int i6) {
        return this.f4471a.m(i3, i4, i5, i6);
    }

    public boolean n() {
        return this.f4471a.n();
    }

    public boolean o(int i3) {
        return this.f4471a.p(i3);
    }

    public C0271j0 p(int i3, int i4, int i5, int i6) {
        return new b(this).c(androidx.core.graphics.b.b(i3, i4, i5, i6)).a();
    }

    void q(androidx.core.graphics.b[] bVarArr) {
        this.f4471a.q(bVarArr);
    }

    void r(androidx.core.graphics.b bVar) {
        this.f4471a.r(bVar);
    }

    void s(C0271j0 c0271j0) {
        this.f4471a.s(c0271j0);
    }

    void t(androidx.core.graphics.b bVar) {
        this.f4471a.t(bVar);
    }

    public WindowInsets u() {
        l lVar = this.f4471a;
        if (lVar instanceof g) {
            return ((g) lVar).f4491c;
        }
        return null;
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$c */
    private static class c extends f {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private static Field f4477e = null;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private static boolean f4478f = false;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private static Constructor f4479g = null;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private static boolean f4480h = false;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private WindowInsets f4481c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private androidx.core.graphics.b f4482d;

        c() {
            this.f4481c = h();
        }

        private static WindowInsets h() {
            if (!f4478f) {
                try {
                    f4477e = WindowInsets.class.getDeclaredField("CONSUMED");
                } catch (ReflectiveOperationException e3) {
                    Log.i("WindowInsetsCompat", "Could not retrieve WindowInsets.CONSUMED field", e3);
                }
                f4478f = true;
            }
            Field field = f4477e;
            if (field != null) {
                try {
                    WindowInsets windowInsets = (WindowInsets) field.get(null);
                    if (windowInsets != null) {
                        return new WindowInsets(windowInsets);
                    }
                } catch (ReflectiveOperationException e4) {
                    Log.i("WindowInsetsCompat", "Could not get value from WindowInsets.CONSUMED field", e4);
                }
            }
            if (!f4480h) {
                try {
                    f4479g = WindowInsets.class.getConstructor(Rect.class);
                } catch (ReflectiveOperationException e5) {
                    Log.i("WindowInsetsCompat", "Could not retrieve WindowInsets(Rect) constructor", e5);
                }
                f4480h = true;
            }
            Constructor constructor = f4479g;
            if (constructor != null) {
                try {
                    return (WindowInsets) constructor.newInstance(new Rect());
                } catch (ReflectiveOperationException e6) {
                    Log.i("WindowInsetsCompat", "Could not invoke WindowInsets(Rect) constructor", e6);
                }
            }
            return null;
        }

        @Override // androidx.core.view.C0271j0.f
        C0271j0 b() {
            a();
            C0271j0 c0271j0V = C0271j0.v(this.f4481c);
            c0271j0V.q(this.f4485b);
            c0271j0V.t(this.f4482d);
            return c0271j0V;
        }

        @Override // androidx.core.view.C0271j0.f
        void d(androidx.core.graphics.b bVar) {
            this.f4482d = bVar;
        }

        @Override // androidx.core.view.C0271j0.f
        void f(androidx.core.graphics.b bVar) {
            WindowInsets windowInsets = this.f4481c;
            if (windowInsets != null) {
                this.f4481c = windowInsets.replaceSystemWindowInsets(bVar.f4321a, bVar.f4322b, bVar.f4323c, bVar.f4324d);
            }
        }

        c(C0271j0 c0271j0) {
            super(c0271j0);
            this.f4481c = c0271j0.u();
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$d */
    private static class d extends f {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final WindowInsets.Builder f4483c;

        d() {
            this.f4483c = r0.a();
        }

        @Override // androidx.core.view.C0271j0.f
        C0271j0 b() {
            a();
            C0271j0 c0271j0V = C0271j0.v(this.f4483c.build());
            c0271j0V.q(this.f4485b);
            return c0271j0V;
        }

        @Override // androidx.core.view.C0271j0.f
        void c(androidx.core.graphics.b bVar) {
            this.f4483c.setMandatorySystemGestureInsets(bVar.e());
        }

        @Override // androidx.core.view.C0271j0.f
        void d(androidx.core.graphics.b bVar) {
            this.f4483c.setStableInsets(bVar.e());
        }

        @Override // androidx.core.view.C0271j0.f
        void e(androidx.core.graphics.b bVar) {
            this.f4483c.setSystemGestureInsets(bVar.e());
        }

        @Override // androidx.core.view.C0271j0.f
        void f(androidx.core.graphics.b bVar) {
            this.f4483c.setSystemWindowInsets(bVar.e());
        }

        @Override // androidx.core.view.C0271j0.f
        void g(androidx.core.graphics.b bVar) {
            this.f4483c.setTappableElementInsets(bVar.e());
        }

        d(C0271j0 c0271j0) {
            WindowInsets.Builder builderA;
            super(c0271j0);
            WindowInsets windowInsetsU = c0271j0.u();
            if (windowInsetsU != null) {
                builderA = q0.a(windowInsetsU);
            } else {
                builderA = r0.a();
            }
            this.f4483c = builderA;
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$h */
    private static class h extends g {

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        private androidx.core.graphics.b f4496m;

        h(C0271j0 c0271j0, WindowInsets windowInsets) {
            super(c0271j0, windowInsets);
            this.f4496m = null;
        }

        @Override // androidx.core.view.C0271j0.l
        C0271j0 b() {
            return C0271j0.v(this.f4491c.consumeStableInsets());
        }

        @Override // androidx.core.view.C0271j0.l
        C0271j0 c() {
            return C0271j0.v(this.f4491c.consumeSystemWindowInsets());
        }

        @Override // androidx.core.view.C0271j0.l
        final androidx.core.graphics.b i() {
            if (this.f4496m == null) {
                this.f4496m = androidx.core.graphics.b.b(this.f4491c.getStableInsetLeft(), this.f4491c.getStableInsetTop(), this.f4491c.getStableInsetRight(), this.f4491c.getStableInsetBottom());
            }
            return this.f4496m;
        }

        @Override // androidx.core.view.C0271j0.l
        boolean n() {
            return this.f4491c.isConsumed();
        }

        @Override // androidx.core.view.C0271j0.l
        public void t(androidx.core.graphics.b bVar) {
            this.f4496m = bVar;
        }

        h(C0271j0 c0271j0, h hVar) {
            super(c0271j0, hVar);
            this.f4496m = null;
            this.f4496m = hVar.f4496m;
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$g */
    private static class g extends l {

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private static boolean f4486h = false;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private static Method f4487i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private static Class f4488j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private static Field f4489k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private static Field f4490l;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final WindowInsets f4491c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private androidx.core.graphics.b[] f4492d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private androidx.core.graphics.b f4493e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private C0271j0 f4494f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        androidx.core.graphics.b f4495g;

        g(C0271j0 c0271j0, WindowInsets windowInsets) {
            super(c0271j0);
            this.f4493e = null;
            this.f4491c = windowInsets;
        }

        private androidx.core.graphics.b u(int i3, boolean z3) {
            androidx.core.graphics.b bVarA = androidx.core.graphics.b.f4320e;
            for (int i4 = 1; i4 <= 256; i4 <<= 1) {
                if ((i3 & i4) != 0) {
                    bVarA = androidx.core.graphics.b.a(bVarA, v(i4, z3));
                }
            }
            return bVarA;
        }

        private androidx.core.graphics.b w() {
            C0271j0 c0271j0 = this.f4494f;
            return c0271j0 != null ? c0271j0.g() : androidx.core.graphics.b.f4320e;
        }

        private androidx.core.graphics.b x(View view) {
            if (Build.VERSION.SDK_INT >= 30) {
                throw new UnsupportedOperationException("getVisibleInsets() should not be called on API >= 30. Use WindowInsets.isVisible() instead.");
            }
            if (!f4486h) {
                z();
            }
            Method method = f4487i;
            if (method != null && f4488j != null && f4489k != null) {
                try {
                    Object objInvoke = method.invoke(view, new Object[0]);
                    if (objInvoke == null) {
                        Log.w("WindowInsetsCompat", "Failed to get visible insets. getViewRootImpl() returned null from the provided view. This means that the view is either not attached or the method has been overridden", new NullPointerException());
                        return null;
                    }
                    Rect rect = (Rect) f4489k.get(f4490l.get(objInvoke));
                    if (rect != null) {
                        return androidx.core.graphics.b.c(rect);
                    }
                    return null;
                } catch (ReflectiveOperationException e3) {
                    Log.e("WindowInsetsCompat", "Failed to get visible insets. (Reflection error). " + e3.getMessage(), e3);
                }
            }
            return null;
        }

        private static void z() {
            try {
                f4487i = View.class.getDeclaredMethod("getViewRootImpl", new Class[0]);
                Class<?> cls = Class.forName("android.view.View$AttachInfo");
                f4488j = cls;
                f4489k = cls.getDeclaredField("mVisibleInsets");
                f4490l = Class.forName("android.view.ViewRootImpl").getDeclaredField("mAttachInfo");
                f4489k.setAccessible(true);
                f4490l.setAccessible(true);
            } catch (ReflectiveOperationException e3) {
                Log.e("WindowInsetsCompat", "Failed to get visible insets. (Reflection error). " + e3.getMessage(), e3);
            }
            f4486h = true;
        }

        @Override // androidx.core.view.C0271j0.l
        void d(View view) {
            androidx.core.graphics.b bVarX = x(view);
            if (bVarX == null) {
                bVarX = androidx.core.graphics.b.f4320e;
            }
            r(bVarX);
        }

        @Override // androidx.core.view.C0271j0.l
        void e(C0271j0 c0271j0) {
            c0271j0.s(this.f4494f);
            c0271j0.r(this.f4495g);
        }

        @Override // androidx.core.view.C0271j0.l
        public boolean equals(Object obj) {
            if (super.equals(obj)) {
                return Objects.equals(this.f4495g, ((g) obj).f4495g);
            }
            return false;
        }

        @Override // androidx.core.view.C0271j0.l
        public androidx.core.graphics.b g(int i3) {
            return u(i3, false);
        }

        @Override // androidx.core.view.C0271j0.l
        final androidx.core.graphics.b k() {
            if (this.f4493e == null) {
                this.f4493e = androidx.core.graphics.b.b(this.f4491c.getSystemWindowInsetLeft(), this.f4491c.getSystemWindowInsetTop(), this.f4491c.getSystemWindowInsetRight(), this.f4491c.getSystemWindowInsetBottom());
            }
            return this.f4493e;
        }

        @Override // androidx.core.view.C0271j0.l
        C0271j0 m(int i3, int i4, int i5, int i6) {
            b bVar = new b(C0271j0.v(this.f4491c));
            bVar.c(C0271j0.m(k(), i3, i4, i5, i6));
            bVar.b(C0271j0.m(i(), i3, i4, i5, i6));
            return bVar.a();
        }

        @Override // androidx.core.view.C0271j0.l
        boolean o() {
            return this.f4491c.isRound();
        }

        @Override // androidx.core.view.C0271j0.l
        boolean p(int i3) {
            for (int i4 = 1; i4 <= 256; i4 <<= 1) {
                if ((i3 & i4) != 0 && !y(i4)) {
                    return false;
                }
            }
            return true;
        }

        @Override // androidx.core.view.C0271j0.l
        public void q(androidx.core.graphics.b[] bVarArr) {
            this.f4492d = bVarArr;
        }

        @Override // androidx.core.view.C0271j0.l
        void r(androidx.core.graphics.b bVar) {
            this.f4495g = bVar;
        }

        @Override // androidx.core.view.C0271j0.l
        void s(C0271j0 c0271j0) {
            this.f4494f = c0271j0;
        }

        protected androidx.core.graphics.b v(int i3, boolean z3) {
            androidx.core.graphics.b bVarG;
            int i4;
            if (i3 == 1) {
                return z3 ? androidx.core.graphics.b.b(0, Math.max(w().f4322b, k().f4322b), 0, 0) : androidx.core.graphics.b.b(0, k().f4322b, 0, 0);
            }
            if (i3 == 2) {
                if (z3) {
                    androidx.core.graphics.b bVarW = w();
                    androidx.core.graphics.b bVarI = i();
                    return androidx.core.graphics.b.b(Math.max(bVarW.f4321a, bVarI.f4321a), 0, Math.max(bVarW.f4323c, bVarI.f4323c), Math.max(bVarW.f4324d, bVarI.f4324d));
                }
                androidx.core.graphics.b bVarK = k();
                C0271j0 c0271j0 = this.f4494f;
                bVarG = c0271j0 != null ? c0271j0.g() : null;
                int iMin = bVarK.f4324d;
                if (bVarG != null) {
                    iMin = Math.min(iMin, bVarG.f4324d);
                }
                return androidx.core.graphics.b.b(bVarK.f4321a, 0, bVarK.f4323c, iMin);
            }
            if (i3 != 8) {
                if (i3 == 16) {
                    return j();
                }
                if (i3 == 32) {
                    return h();
                }
                if (i3 == 64) {
                    return l();
                }
                if (i3 != 128) {
                    return androidx.core.graphics.b.f4320e;
                }
                C0271j0 c0271j02 = this.f4494f;
                r rVarE = c0271j02 != null ? c0271j02.e() : f();
                return rVarE != null ? androidx.core.graphics.b.b(rVarE.b(), rVarE.d(), rVarE.c(), rVarE.a()) : androidx.core.graphics.b.f4320e;
            }
            androidx.core.graphics.b[] bVarArr = this.f4492d;
            bVarG = bVarArr != null ? bVarArr[m.b(8)] : null;
            if (bVarG != null) {
                return bVarG;
            }
            androidx.core.graphics.b bVarK2 = k();
            androidx.core.graphics.b bVarW2 = w();
            int i5 = bVarK2.f4324d;
            if (i5 > bVarW2.f4324d) {
                return androidx.core.graphics.b.b(0, 0, 0, i5);
            }
            androidx.core.graphics.b bVar = this.f4495g;
            return (bVar == null || bVar.equals(androidx.core.graphics.b.f4320e) || (i4 = this.f4495g.f4324d) <= bVarW2.f4324d) ? androidx.core.graphics.b.f4320e : androidx.core.graphics.b.b(0, 0, 0, i4);
        }

        protected boolean y(int i3) {
            if (i3 != 1 && i3 != 2) {
                if (i3 == 4) {
                    return false;
                }
                if (i3 != 8 && i3 != 128) {
                    return true;
                }
            }
            return !v(i3, false).equals(androidx.core.graphics.b.f4320e);
        }

        g(C0271j0 c0271j0, g gVar) {
            this(c0271j0, new WindowInsets(gVar.f4491c));
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$j */
    private static class j extends i {

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        private androidx.core.graphics.b f4497n;

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        private androidx.core.graphics.b f4498o;

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        private androidx.core.graphics.b f4499p;

        j(C0271j0 c0271j0, WindowInsets windowInsets) {
            super(c0271j0, windowInsets);
            this.f4497n = null;
            this.f4498o = null;
            this.f4499p = null;
        }

        @Override // androidx.core.view.C0271j0.l
        androidx.core.graphics.b h() {
            if (this.f4498o == null) {
                this.f4498o = androidx.core.graphics.b.d(this.f4491c.getMandatorySystemGestureInsets());
            }
            return this.f4498o;
        }

        @Override // androidx.core.view.C0271j0.l
        androidx.core.graphics.b j() {
            if (this.f4497n == null) {
                this.f4497n = androidx.core.graphics.b.d(this.f4491c.getSystemGestureInsets());
            }
            return this.f4497n;
        }

        @Override // androidx.core.view.C0271j0.l
        androidx.core.graphics.b l() {
            if (this.f4499p == null) {
                this.f4499p = androidx.core.graphics.b.d(this.f4491c.getTappableElementInsets());
            }
            return this.f4499p;
        }

        @Override // androidx.core.view.C0271j0.g, androidx.core.view.C0271j0.l
        C0271j0 m(int i3, int i4, int i5, int i6) {
            return C0271j0.v(this.f4491c.inset(i3, i4, i5, i6));
        }

        @Override // androidx.core.view.C0271j0.h, androidx.core.view.C0271j0.l
        public void t(androidx.core.graphics.b bVar) {
        }

        j(C0271j0 c0271j0, j jVar) {
            super(c0271j0, jVar);
            this.f4497n = null;
            this.f4498o = null;
            this.f4499p = null;
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.j0$b */
    public static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final f f4476a;

        public b() {
            int i3 = Build.VERSION.SDK_INT;
            if (i3 >= 30) {
                this.f4476a = new e();
            } else if (i3 >= 29) {
                this.f4476a = new d();
            } else {
                this.f4476a = new c();
            }
        }

        public C0271j0 a() {
            return this.f4476a.b();
        }

        public b b(androidx.core.graphics.b bVar) {
            this.f4476a.d(bVar);
            return this;
        }

        public b c(androidx.core.graphics.b bVar) {
            this.f4476a.f(bVar);
            return this;
        }

        public b(C0271j0 c0271j0) {
            int i3 = Build.VERSION.SDK_INT;
            if (i3 >= 30) {
                this.f4476a = new e(c0271j0);
            } else if (i3 >= 29) {
                this.f4476a = new d(c0271j0);
            } else {
                this.f4476a = new c(c0271j0);
            }
        }
    }

    public C0271j0(C0271j0 c0271j0) {
        if (c0271j0 != null) {
            l lVar = c0271j0.f4471a;
            int i3 = Build.VERSION.SDK_INT;
            if (i3 >= 30 && (lVar instanceof k)) {
                this.f4471a = new k(this, (k) lVar);
            } else if (i3 >= 29 && (lVar instanceof j)) {
                this.f4471a = new j(this, (j) lVar);
            } else if (i3 >= 28 && (lVar instanceof i)) {
                this.f4471a = new i(this, (i) lVar);
            } else if (lVar instanceof h) {
                this.f4471a = new h(this, (h) lVar);
            } else if (lVar instanceof g) {
                this.f4471a = new g(this, (g) lVar);
            } else {
                this.f4471a = new l(this);
            }
            lVar.e(this);
            return;
        }
        this.f4471a = new l(this);
    }
}
