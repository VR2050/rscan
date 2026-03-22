package p005b.p143g.p144a.p166q;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.util.Log;
import androidx.annotation.DrawableRes;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1555e;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p150t.C1644l;
import p005b.p143g.p144a.p147m.p150t.C1650r;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1670l;
import p005b.p143g.p144a.p147m.p156v.p159e.C1724a;
import p005b.p143g.p144a.p166q.p167i.InterfaceC1789h;
import p005b.p143g.p144a.p166q.p167i.InterfaceC1790i;
import p005b.p143g.p144a.p166q.p168j.C1792a;
import p005b.p143g.p144a.p166q.p168j.InterfaceC1794c;
import p005b.p143g.p144a.p170s.C1803e;
import p005b.p143g.p144a.p170s.C1807i;
import p005b.p143g.p144a.p170s.p171j.AbstractC1811d;

/* renamed from: b.g.a.q.h */
/* loaded from: classes.dex */
public final class C1781h<R> implements InterfaceC1775b, InterfaceC1789h, InterfaceC1780g {

    /* renamed from: a */
    public static final boolean f2689a = Log.isLoggable("Request", 2);

    /* renamed from: A */
    @GuardedBy("requestLock")
    public int f2690A;

    /* renamed from: B */
    @GuardedBy("requestLock")
    public int f2691B;

    /* renamed from: C */
    @GuardedBy("requestLock")
    public boolean f2692C;

    /* renamed from: D */
    @Nullable
    public RuntimeException f2693D;

    /* renamed from: b */
    @Nullable
    public final String f2694b;

    /* renamed from: c */
    public final AbstractC1811d f2695c;

    /* renamed from: d */
    public final Object f2696d;

    /* renamed from: e */
    @Nullable
    public final InterfaceC1778e<R> f2697e;

    /* renamed from: f */
    public final InterfaceC1776c f2698f;

    /* renamed from: g */
    public final Context f2699g;

    /* renamed from: h */
    public final C1555e f2700h;

    /* renamed from: i */
    @Nullable
    public final Object f2701i;

    /* renamed from: j */
    public final Class<R> f2702j;

    /* renamed from: k */
    public final AbstractC1774a<?> f2703k;

    /* renamed from: l */
    public final int f2704l;

    /* renamed from: m */
    public final int f2705m;

    /* renamed from: n */
    public final EnumC1556f f2706n;

    /* renamed from: o */
    public final InterfaceC1790i<R> f2707o;

    /* renamed from: p */
    @Nullable
    public final List<InterfaceC1778e<R>> f2708p;

    /* renamed from: q */
    public final InterfaceC1794c<? super R> f2709q;

    /* renamed from: r */
    public final Executor f2710r;

    /* renamed from: s */
    @GuardedBy("requestLock")
    public InterfaceC1655w<R> f2711s;

    /* renamed from: t */
    @GuardedBy("requestLock")
    public C1644l.d f2712t;

    /* renamed from: u */
    @GuardedBy("requestLock")
    public long f2713u;

    /* renamed from: v */
    public volatile C1644l f2714v;

    /* renamed from: w */
    @GuardedBy("requestLock")
    public int f2715w;

    /* renamed from: x */
    @Nullable
    @GuardedBy("requestLock")
    public Drawable f2716x;

    /* renamed from: y */
    @Nullable
    @GuardedBy("requestLock")
    public Drawable f2717y;

    /* renamed from: z */
    @Nullable
    @GuardedBy("requestLock")
    public Drawable f2718z;

    public C1781h(Context context, C1555e c1555e, @NonNull Object obj, @Nullable Object obj2, Class<R> cls, AbstractC1774a<?> abstractC1774a, int i2, int i3, EnumC1556f enumC1556f, InterfaceC1790i<R> interfaceC1790i, @Nullable InterfaceC1778e<R> interfaceC1778e, @Nullable List<InterfaceC1778e<R>> list, InterfaceC1776c interfaceC1776c, C1644l c1644l, InterfaceC1794c<? super R> interfaceC1794c, Executor executor) {
        this.f2694b = f2689a ? String.valueOf(hashCode()) : null;
        this.f2695c = new AbstractC1811d.b();
        this.f2696d = obj;
        this.f2699g = context;
        this.f2700h = c1555e;
        this.f2701i = obj2;
        this.f2702j = cls;
        this.f2703k = abstractC1774a;
        this.f2704l = i2;
        this.f2705m = i3;
        this.f2706n = enumC1556f;
        this.f2707o = interfaceC1790i;
        this.f2697e = interfaceC1778e;
        this.f2708p = list;
        this.f2698f = interfaceC1776c;
        this.f2714v = c1644l;
        this.f2709q = interfaceC1794c;
        this.f2710r = executor;
        this.f2715w = 1;
        if (this.f2693D == null && c1555e.f1842i) {
            this.f2693D = new RuntimeException("Glide request origin trace");
        }
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1789h
    /* renamed from: a */
    public void mo1111a(int i2, int i3) {
        Object obj;
        int i4 = i2;
        this.f2695c.mo1155a();
        Object obj2 = this.f2696d;
        synchronized (obj2) {
            try {
                boolean z = f2689a;
                if (z) {
                    C1803e.m1138a(this.f2713u);
                }
                if (this.f2715w == 3) {
                    this.f2715w = 2;
                    float f2 = this.f2703k.f2657e;
                    if (i4 != Integer.MIN_VALUE) {
                        i4 = Math.round(i4 * f2);
                    }
                    this.f2690A = i4;
                    this.f2691B = i3 == Integer.MIN_VALUE ? i3 : Math.round(f2 * i3);
                    if (z) {
                        C1803e.m1138a(this.f2713u);
                    }
                    C1644l c1644l = this.f2714v;
                    C1555e c1555e = this.f2700h;
                    Object obj3 = this.f2701i;
                    AbstractC1774a<?> abstractC1774a = this.f2703k;
                    try {
                        obj = obj2;
                        try {
                            try {
                                this.f2712t = c1644l.m933b(c1555e, obj3, abstractC1774a.f2667o, this.f2690A, this.f2691B, abstractC1774a.f2674v, this.f2702j, this.f2706n, abstractC1774a.f2658f, abstractC1774a.f2673u, abstractC1774a.f2668p, abstractC1774a.f2654B, abstractC1774a.f2672t, abstractC1774a.f2664l, abstractC1774a.f2678z, abstractC1774a.f2655C, abstractC1774a.f2653A, this, this.f2710r);
                                if (this.f2715w != 2) {
                                    this.f2712t = null;
                                }
                                if (z) {
                                    C1803e.m1138a(this.f2713u);
                                }
                            } catch (Throwable th) {
                                th = th;
                                while (true) {
                                    try {
                                        throw th;
                                    } catch (Throwable th2) {
                                        th = th2;
                                    }
                                }
                            }
                        } catch (Throwable th3) {
                            th = th3;
                        }
                    } catch (Throwable th4) {
                        th = th4;
                        obj = obj2;
                    }
                }
            } catch (Throwable th5) {
                th = th5;
                obj = obj2;
            }
        }
    }

    @Override // p005b.p143g.p144a.p166q.InterfaceC1775b
    /* renamed from: b */
    public boolean mo1100b() {
        boolean z;
        synchronized (this.f2696d) {
            z = this.f2715w == 6;
        }
        return z;
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x007d A[Catch: all -> 0x0099, TryCatch #0 {, blocks: (B:4:0x0003, B:6:0x0018, B:8:0x0022, B:9:0x002a, B:12:0x0031, B:13:0x003b, B:16:0x003d, B:20:0x0045, B:21:0x004c, B:23:0x004e, B:25:0x005a, B:26:0x0067, B:29:0x0086, B:31:0x008a, B:32:0x008f, B:34:0x006d, B:36:0x0071, B:41:0x007d, B:43:0x0062, B:44:0x0091, B:45:0x0098), top: B:3:0x0003 }] */
    @Override // p005b.p143g.p144a.p166q.InterfaceC1775b
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1101c() {
        /*
            r5 = this;
            java.lang.Object r0 = r5.f2696d
            monitor-enter(r0)
            r5.m1112e()     // Catch: java.lang.Throwable -> L99
            b.g.a.s.j.d r1 = r5.f2695c     // Catch: java.lang.Throwable -> L99
            r1.mo1155a()     // Catch: java.lang.Throwable -> L99
            int r1 = p005b.p143g.p144a.p170s.C1803e.f2759b     // Catch: java.lang.Throwable -> L99
            long r1 = android.os.SystemClock.elapsedRealtimeNanos()     // Catch: java.lang.Throwable -> L99
            r5.f2713u = r1     // Catch: java.lang.Throwable -> L99
            java.lang.Object r1 = r5.f2701i     // Catch: java.lang.Throwable -> L99
            r2 = 3
            if (r1 != 0) goto L3d
            int r1 = r5.f2704l     // Catch: java.lang.Throwable -> L99
            int r3 = r5.f2705m     // Catch: java.lang.Throwable -> L99
            boolean r1 = p005b.p143g.p144a.p170s.C1807i.m1152i(r1, r3)     // Catch: java.lang.Throwable -> L99
            if (r1 == 0) goto L2a
            int r1 = r5.f2704l     // Catch: java.lang.Throwable -> L99
            r5.f2690A = r1     // Catch: java.lang.Throwable -> L99
            int r1 = r5.f2705m     // Catch: java.lang.Throwable -> L99
            r5.f2691B = r1     // Catch: java.lang.Throwable -> L99
        L2a:
            android.graphics.drawable.Drawable r1 = r5.m1114g()     // Catch: java.lang.Throwable -> L99
            if (r1 != 0) goto L31
            r2 = 5
        L31:
            b.g.a.m.t.r r1 = new b.g.a.m.t.r     // Catch: java.lang.Throwable -> L99
            java.lang.String r3 = "Received null model"
            r1.<init>(r3)     // Catch: java.lang.Throwable -> L99
            r5.m1119l(r1, r2)     // Catch: java.lang.Throwable -> L99
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L99
            return
        L3d:
            int r1 = r5.f2715w     // Catch: java.lang.Throwable -> L99
            r3 = 2
            if (r1 == r3) goto L91
            r4 = 4
            if (r1 != r4) goto L4e
            b.g.a.m.t.w<R> r1 = r5.f2711s     // Catch: java.lang.Throwable -> L99
            b.g.a.m.a r2 = p005b.p143g.p144a.p147m.EnumC1569a.MEMORY_CACHE     // Catch: java.lang.Throwable -> L99
            r5.m1120m(r1, r2)     // Catch: java.lang.Throwable -> L99
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L99
            return
        L4e:
            r5.f2715w = r2     // Catch: java.lang.Throwable -> L99
            int r1 = r5.f2704l     // Catch: java.lang.Throwable -> L99
            int r4 = r5.f2705m     // Catch: java.lang.Throwable -> L99
            boolean r1 = p005b.p143g.p144a.p170s.C1807i.m1152i(r1, r4)     // Catch: java.lang.Throwable -> L99
            if (r1 == 0) goto L62
            int r1 = r5.f2704l     // Catch: java.lang.Throwable -> L99
            int r4 = r5.f2705m     // Catch: java.lang.Throwable -> L99
            r5.mo1111a(r1, r4)     // Catch: java.lang.Throwable -> L99
            goto L67
        L62:
            b.g.a.q.i.i<R> r1 = r5.f2707o     // Catch: java.lang.Throwable -> L99
            r1.getSize(r5)     // Catch: java.lang.Throwable -> L99
        L67:
            int r1 = r5.f2715w     // Catch: java.lang.Throwable -> L99
            if (r1 == r3) goto L6d
            if (r1 != r2) goto L86
        L6d:
            b.g.a.q.c r1 = r5.f2698f     // Catch: java.lang.Throwable -> L99
            if (r1 == 0) goto L7a
            boolean r1 = r1.m1105c(r5)     // Catch: java.lang.Throwable -> L99
            if (r1 == 0) goto L78
            goto L7a
        L78:
            r1 = 0
            goto L7b
        L7a:
            r1 = 1
        L7b:
            if (r1 == 0) goto L86
            b.g.a.q.i.i<R> r1 = r5.f2707o     // Catch: java.lang.Throwable -> L99
            android.graphics.drawable.Drawable r2 = r5.m1115h()     // Catch: java.lang.Throwable -> L99
            r1.onLoadStarted(r2)     // Catch: java.lang.Throwable -> L99
        L86:
            boolean r1 = p005b.p143g.p144a.p166q.C1781h.f2689a     // Catch: java.lang.Throwable -> L99
            if (r1 == 0) goto L8f
            long r1 = r5.f2713u     // Catch: java.lang.Throwable -> L99
            p005b.p143g.p144a.p170s.C1803e.m1138a(r1)     // Catch: java.lang.Throwable -> L99
        L8f:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L99
            return
        L91:
            java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException     // Catch: java.lang.Throwable -> L99
            java.lang.String r2 = "Cannot restart a running request"
            r1.<init>(r2)     // Catch: java.lang.Throwable -> L99
            throw r1     // Catch: java.lang.Throwable -> L99
        L99:
            r1 = move-exception
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L99
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p166q.C1781h.mo1101c():void");
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x002e A[Catch: all -> 0x0042, TryCatch #0 {, blocks: (B:4:0x0003, B:6:0x0010, B:9:0x0012, B:11:0x001a, B:12:0x001e, B:14:0x0022, B:19:0x002e, B:20:0x0037, B:21:0x0039), top: B:3:0x0003 }] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x003c  */
    /* JADX WARN: Removed duplicated region for block: B:25:? A[RETURN, SYNTHETIC] */
    @Override // p005b.p143g.p144a.p166q.InterfaceC1775b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void clear() {
        /*
            r5 = this;
            java.lang.Object r0 = r5.f2696d
            monitor-enter(r0)
            r5.m1112e()     // Catch: java.lang.Throwable -> L42
            b.g.a.s.j.d r1 = r5.f2695c     // Catch: java.lang.Throwable -> L42
            r1.mo1155a()     // Catch: java.lang.Throwable -> L42
            int r1 = r5.f2715w     // Catch: java.lang.Throwable -> L42
            r2 = 6
            if (r1 != r2) goto L12
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L42
            return
        L12:
            r5.m1113f()     // Catch: java.lang.Throwable -> L42
            b.g.a.m.t.w<R> r1 = r5.f2711s     // Catch: java.lang.Throwable -> L42
            r3 = 0
            if (r1 == 0) goto L1d
            r5.f2711s = r3     // Catch: java.lang.Throwable -> L42
            goto L1e
        L1d:
            r1 = r3
        L1e:
            b.g.a.q.c r3 = r5.f2698f     // Catch: java.lang.Throwable -> L42
            if (r3 == 0) goto L2b
            boolean r3 = r3.m1108f(r5)     // Catch: java.lang.Throwable -> L42
            if (r3 == 0) goto L29
            goto L2b
        L29:
            r3 = 0
            goto L2c
        L2b:
            r3 = 1
        L2c:
            if (r3 == 0) goto L37
            b.g.a.q.i.i<R> r3 = r5.f2707o     // Catch: java.lang.Throwable -> L42
            android.graphics.drawable.Drawable r4 = r5.m1115h()     // Catch: java.lang.Throwable -> L42
            r3.onLoadCleared(r4)     // Catch: java.lang.Throwable -> L42
        L37:
            r5.f2715w = r2     // Catch: java.lang.Throwable -> L42
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L42
            if (r1 == 0) goto L41
            b.g.a.m.t.l r0 = r5.f2714v
            r0.m936f(r1)
        L41:
            return
        L42:
            r1 = move-exception
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L42
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p166q.C1781h.clear():void");
    }

    @Override // p005b.p143g.p144a.p166q.InterfaceC1775b
    /* renamed from: d */
    public boolean mo1102d() {
        boolean z;
        synchronized (this.f2696d) {
            z = this.f2715w == 4;
        }
        return z;
    }

    @GuardedBy("requestLock")
    /* renamed from: e */
    public final void m1112e() {
        if (this.f2692C) {
            throw new IllegalStateException("You can't start or clear loads in RequestListener or Target callbacks. If you're trying to start a fallback request when a load fails, use RequestBuilder#error(RequestBuilder). Otherwise consider posting your into() or clear() calls to the main thread using a Handler instead.");
        }
    }

    @GuardedBy("requestLock")
    /* renamed from: f */
    public final void m1113f() {
        m1112e();
        this.f2695c.mo1155a();
        this.f2707o.removeCallback(this);
        C1644l.d dVar = this.f2712t;
        if (dVar != null) {
            synchronized (C1644l.this) {
                dVar.f2249a.m945h(dVar.f2250b);
            }
            this.f2712t = null;
        }
    }

    @GuardedBy("requestLock")
    /* renamed from: g */
    public final Drawable m1114g() {
        int i2;
        if (this.f2718z == null) {
            AbstractC1774a<?> abstractC1774a = this.f2703k;
            Drawable drawable = abstractC1774a.f2670r;
            this.f2718z = drawable;
            if (drawable == null && (i2 = abstractC1774a.f2671s) > 0) {
                this.f2718z = m1118k(i2);
            }
        }
        return this.f2718z;
    }

    @GuardedBy("requestLock")
    /* renamed from: h */
    public final Drawable m1115h() {
        int i2;
        if (this.f2717y == null) {
            AbstractC1774a<?> abstractC1774a = this.f2703k;
            Drawable drawable = abstractC1774a.f2662j;
            this.f2717y = drawable;
            if (drawable == null && (i2 = abstractC1774a.f2663k) > 0) {
                this.f2717y = m1118k(i2);
            }
        }
        return this.f2717y;
    }

    /* renamed from: i */
    public boolean m1116i(InterfaceC1775b interfaceC1775b) {
        int i2;
        int i3;
        Object obj;
        Class<R> cls;
        AbstractC1774a<?> abstractC1774a;
        EnumC1556f enumC1556f;
        int size;
        int i4;
        int i5;
        Object obj2;
        Class<R> cls2;
        AbstractC1774a<?> abstractC1774a2;
        EnumC1556f enumC1556f2;
        int size2;
        if (!(interfaceC1775b instanceof C1781h)) {
            return false;
        }
        synchronized (this.f2696d) {
            i2 = this.f2704l;
            i3 = this.f2705m;
            obj = this.f2701i;
            cls = this.f2702j;
            abstractC1774a = this.f2703k;
            enumC1556f = this.f2706n;
            List<InterfaceC1778e<R>> list = this.f2708p;
            size = list != null ? list.size() : 0;
        }
        C1781h c1781h = (C1781h) interfaceC1775b;
        synchronized (c1781h.f2696d) {
            i4 = c1781h.f2704l;
            i5 = c1781h.f2705m;
            obj2 = c1781h.f2701i;
            cls2 = c1781h.f2702j;
            abstractC1774a2 = c1781h.f2703k;
            enumC1556f2 = c1781h.f2706n;
            List<InterfaceC1778e<R>> list2 = c1781h.f2708p;
            size2 = list2 != null ? list2.size() : 0;
        }
        if (i2 == i4 && i3 == i5) {
            char[] cArr = C1807i.f2767a;
            if ((obj == null ? obj2 == null : obj instanceof InterfaceC1670l ? ((InterfaceC1670l) obj).m975a(obj2) : obj.equals(obj2)) && cls.equals(cls2) && abstractC1774a.equals(abstractC1774a2) && enumC1556f == enumC1556f2 && size == size2) {
                return true;
            }
        }
        return false;
    }

    @Override // p005b.p143g.p144a.p166q.InterfaceC1775b
    public boolean isRunning() {
        boolean z;
        synchronized (this.f2696d) {
            int i2 = this.f2715w;
            z = i2 == 2 || i2 == 3;
        }
        return z;
    }

    @GuardedBy("requestLock")
    /* renamed from: j */
    public final boolean m1117j() {
        InterfaceC1776c interfaceC1776c = this.f2698f;
        return interfaceC1776c == null || !interfaceC1776c.getRoot().m1104b();
    }

    @GuardedBy("requestLock")
    /* renamed from: k */
    public final Drawable m1118k(@DrawableRes int i2) {
        Resources.Theme theme = this.f2703k.f2676x;
        if (theme == null) {
            theme = this.f2699g.getTheme();
        }
        C1555e c1555e = this.f2700h;
        return C1724a.m1027a(c1555e, c1555e, i2, theme);
    }

    /* renamed from: l */
    public final void m1119l(C1650r c1650r, int i2) {
        boolean z;
        this.f2695c.mo1155a();
        synchronized (this.f2696d) {
            Objects.requireNonNull(c1650r);
            int i3 = this.f2700h.f1843j;
            if (i3 <= i2) {
                String str = "Load failed for " + this.f2701i + " with size [" + this.f2690A + "x" + this.f2691B + "]";
                if (i3 <= 4) {
                    ArrayList arrayList = new ArrayList();
                    c1650r.m953a(c1650r, arrayList);
                    int size = arrayList.size();
                    int i4 = 0;
                    while (i4 < size) {
                        int i5 = i4 + 1;
                        i4 = i5;
                    }
                }
            }
            this.f2712t = null;
            this.f2715w = 5;
            boolean z2 = true;
            this.f2692C = true;
            try {
                List<InterfaceC1778e<R>> list = this.f2708p;
                if (list != null) {
                    Iterator<InterfaceC1778e<R>> it = list.iterator();
                    z = false;
                    while (it.hasNext()) {
                        z |= it.next().mo207a(c1650r, this.f2701i, this.f2707o, m1117j());
                    }
                } else {
                    z = false;
                }
                InterfaceC1778e<R> interfaceC1778e = this.f2697e;
                if (interfaceC1778e == null || !interfaceC1778e.mo207a(c1650r, this.f2701i, this.f2707o, m1117j())) {
                    z2 = false;
                }
                if (!(z | z2)) {
                    m1122o();
                }
                this.f2692C = false;
                InterfaceC1776c interfaceC1776c = this.f2698f;
                if (interfaceC1776c != null) {
                    interfaceC1776c.m1103a(this);
                }
            } catch (Throwable th) {
                this.f2692C = false;
                throw th;
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: m */
    public void m1120m(InterfaceC1655w<?> interfaceC1655w, EnumC1569a enumC1569a) {
        C1781h c1781h;
        Throwable th;
        this.f2695c.mo1155a();
        InterfaceC1655w<?> interfaceC1655w2 = null;
        try {
            synchronized (this.f2696d) {
                try {
                    this.f2712t = null;
                    if (interfaceC1655w == null) {
                        m1119l(new C1650r("Expected to receive a Resource<R> with an object of " + this.f2702j + " inside, but instead got null."), 5);
                        return;
                    }
                    Object obj = interfaceC1655w.get();
                    try {
                        if (obj != null && this.f2702j.isAssignableFrom(obj.getClass())) {
                            InterfaceC1776c interfaceC1776c = this.f2698f;
                            if (interfaceC1776c == null || interfaceC1776c.m1106d(this)) {
                                m1121n(interfaceC1655w, obj, enumC1569a);
                                return;
                            }
                            this.f2711s = null;
                            this.f2715w = 4;
                            this.f2714v.m936f(interfaceC1655w);
                        }
                        this.f2711s = null;
                        StringBuilder sb = new StringBuilder();
                        sb.append("Expected to receive an object of ");
                        sb.append(this.f2702j);
                        sb.append(" but instead got ");
                        sb.append(obj != null ? obj.getClass() : "");
                        sb.append("{");
                        sb.append(obj);
                        sb.append("} inside Resource{");
                        sb.append(interfaceC1655w);
                        sb.append("}.");
                        sb.append(obj != null ? "" : " To indicate failure return a null Resource object, rather than a Resource object containing null data.");
                        m1119l(new C1650r(sb.toString()), 5);
                        this.f2714v.m936f(interfaceC1655w);
                    } catch (Throwable th2) {
                        th = th2;
                        interfaceC1655w2 = interfaceC1655w;
                        c1781h = this;
                        while (true) {
                            try {
                                try {
                                    throw th;
                                } catch (Throwable th3) {
                                    th = th3;
                                    if (interfaceC1655w2 != null) {
                                        c1781h.f2714v.m936f(interfaceC1655w2);
                                    }
                                    throw th;
                                }
                            } catch (Throwable th4) {
                                th = th4;
                                c1781h = c1781h;
                            }
                            th = th4;
                            c1781h = c1781h;
                        }
                    }
                } catch (Throwable th5) {
                    th = th5;
                    c1781h = this;
                }
            }
        } catch (Throwable th6) {
            th = th6;
            c1781h = this;
        }
    }

    @GuardedBy("requestLock")
    /* renamed from: n */
    public final void m1121n(InterfaceC1655w<R> interfaceC1655w, R r, EnumC1569a enumC1569a) {
        boolean z;
        boolean m1117j = m1117j();
        this.f2715w = 4;
        this.f2711s = interfaceC1655w;
        if (this.f2700h.f1843j <= 3) {
            StringBuilder m586H = C1499a.m586H("Finished loading ");
            m586H.append(r.getClass().getSimpleName());
            m586H.append(" from ");
            m586H.append(enumC1569a);
            m586H.append(" for ");
            m586H.append(this.f2701i);
            m586H.append(" with size [");
            m586H.append(this.f2690A);
            m586H.append("x");
            m586H.append(this.f2691B);
            m586H.append("] in ");
            m586H.append(C1803e.m1138a(this.f2713u));
            m586H.append(" ms");
            m586H.toString();
        }
        boolean z2 = true;
        this.f2692C = true;
        try {
            List<InterfaceC1778e<R>> list = this.f2708p;
            if (list != null) {
                Iterator<InterfaceC1778e<R>> it = list.iterator();
                z = false;
                while (it.hasNext()) {
                    z |= it.next().mo208b(r, this.f2701i, this.f2707o, enumC1569a, m1117j);
                }
            } else {
                z = false;
            }
            InterfaceC1778e<R> interfaceC1778e = this.f2697e;
            if (interfaceC1778e == null || !interfaceC1778e.mo208b(r, this.f2701i, this.f2707o, enumC1569a, m1117j)) {
                z2 = false;
            }
            if (!(z2 | z)) {
                Objects.requireNonNull(this.f2709q);
                this.f2707o.onResourceReady(r, C1792a.f2736a);
            }
            this.f2692C = false;
            InterfaceC1776c interfaceC1776c = this.f2698f;
            if (interfaceC1776c != null) {
                interfaceC1776c.m1107e(this);
            }
        } catch (Throwable th) {
            this.f2692C = false;
            throw th;
        }
    }

    @GuardedBy("requestLock")
    /* renamed from: o */
    public final void m1122o() {
        int i2;
        InterfaceC1776c interfaceC1776c = this.f2698f;
        if (interfaceC1776c == null || interfaceC1776c.m1105c(this)) {
            Drawable m1114g = this.f2701i == null ? m1114g() : null;
            if (m1114g == null) {
                if (this.f2716x == null) {
                    AbstractC1774a<?> abstractC1774a = this.f2703k;
                    Drawable drawable = abstractC1774a.f2660h;
                    this.f2716x = drawable;
                    if (drawable == null && (i2 = abstractC1774a.f2661i) > 0) {
                        this.f2716x = m1118k(i2);
                    }
                }
                m1114g = this.f2716x;
            }
            if (m1114g == null) {
                m1114g = m1115h();
            }
            this.f2707o.onLoadFailed(m1114g);
        }
    }

    @Override // p005b.p143g.p144a.p166q.InterfaceC1775b
    public void pause() {
        synchronized (this.f2696d) {
            if (isRunning()) {
                clear();
            }
        }
    }
}
