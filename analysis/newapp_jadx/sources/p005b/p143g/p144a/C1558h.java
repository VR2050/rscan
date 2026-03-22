package p005b.p143g.p144a;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.widget.ImageView;
import androidx.annotation.CheckResult;
import androidx.annotation.DrawableRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RawRes;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p150t.AbstractC1643k;
import p005b.p143g.p144a.p147m.p150t.C1644l;
import p005b.p143g.p144a.p163n.C1760n;
import p005b.p143g.p144a.p166q.AbstractC1774a;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p143g.p144a.p166q.C1781h;
import p005b.p143g.p144a.p166q.InterfaceC1775b;
import p005b.p143g.p144a.p166q.InterfaceC1776c;
import p005b.p143g.p144a.p166q.InterfaceC1778e;
import p005b.p143g.p144a.p166q.p167i.InterfaceC1790i;
import p005b.p143g.p144a.p166q.p168j.C1792a;
import p005b.p143g.p144a.p169r.C1795a;
import p005b.p143g.p144a.p169r.C1796b;
import p005b.p143g.p144a.p169r.C1798d;
import p005b.p143g.p144a.p170s.C1802d;

/* renamed from: b.g.a.h */
/* loaded from: classes.dex */
public class C1558h<TranscodeType> extends AbstractC1774a<C1558h<TranscodeType>> implements Cloneable {

    /* renamed from: D */
    public final Context f1860D;

    /* renamed from: E */
    public final ComponentCallbacks2C1559i f1861E;

    /* renamed from: F */
    public final Class<TranscodeType> f1862F;

    /* renamed from: G */
    public final C1555e f1863G;

    /* renamed from: H */
    @NonNull
    public AbstractC1560j<?, ? super TranscodeType> f1864H;

    /* renamed from: I */
    @Nullable
    public Object f1865I;

    /* renamed from: J */
    @Nullable
    public List<InterfaceC1778e<TranscodeType>> f1866J;

    /* renamed from: K */
    public boolean f1867K = true;

    /* renamed from: L */
    public boolean f1868L;

    /* renamed from: b.g.a.h$a */
    public static /* synthetic */ class a {

        /* renamed from: a */
        public static final /* synthetic */ int[] f1869a;

        /* renamed from: b */
        public static final /* synthetic */ int[] f1870b;

        static {
            EnumC1556f.values();
            int[] iArr = new int[4];
            f1870b = iArr;
            try {
                iArr[3] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f1870b[2] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f1870b[1] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f1870b[0] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            int[] iArr2 = new int[ImageView.ScaleType.values().length];
            f1869a = iArr2;
            try {
                iArr2[ImageView.ScaleType.CENTER_CROP.ordinal()] = 1;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f1869a[ImageView.ScaleType.CENTER_INSIDE.ordinal()] = 2;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                f1869a[ImageView.ScaleType.FIT_CENTER.ordinal()] = 3;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                f1869a[ImageView.ScaleType.FIT_START.ordinal()] = 4;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                f1869a[ImageView.ScaleType.FIT_END.ordinal()] = 5;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                f1869a[ImageView.ScaleType.FIT_XY.ordinal()] = 6;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                f1869a[ImageView.ScaleType.CENTER.ordinal()] = 7;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                f1869a[ImageView.ScaleType.MATRIX.ordinal()] = 8;
            } catch (NoSuchFieldError unused12) {
            }
        }
    }

    static {
        new C1779f().mo1086i(AbstractC1643k.f2224c).mo1099z(EnumC1556f.LOW).mo1075E(true);
    }

    @SuppressLint({"CheckResult"})
    public C1558h(@NonNull ComponentCallbacks2C1553c componentCallbacks2C1553c, ComponentCallbacks2C1559i componentCallbacks2C1559i, Class<TranscodeType> cls, Context context) {
        C1779f c1779f;
        this.f1861E = componentCallbacks2C1559i;
        this.f1862F = cls;
        this.f1860D = context;
        C1555e c1555e = componentCallbacks2C1559i.f1873f.f1813i;
        AbstractC1560j abstractC1560j = c1555e.f1840g.get(cls);
        if (abstractC1560j == null) {
            for (Map.Entry<Class<?>, AbstractC1560j<?, ?>> entry : c1555e.f1840g.entrySet()) {
                if (entry.getKey().isAssignableFrom(cls)) {
                    abstractC1560j = (AbstractC1560j) entry.getValue();
                }
            }
        }
        this.f1864H = abstractC1560j == null ? C1555e.f1834a : abstractC1560j;
        this.f1863G = componentCallbacks2C1553c.f1813i;
        Iterator<InterfaceC1778e<Object>> it = componentCallbacks2C1559i.f1882o.iterator();
        while (it.hasNext()) {
            mo751L((InterfaceC1778e) it.next());
        }
        synchronized (componentCallbacks2C1559i) {
            c1779f = componentCallbacks2C1559i.f1883p;
        }
        mo766a(c1779f);
    }

    @NonNull
    @CheckResult
    /* renamed from: L */
    public C1558h<TranscodeType> mo751L(@Nullable InterfaceC1778e<TranscodeType> interfaceC1778e) {
        if (interfaceC1778e != null) {
            if (this.f1866J == null) {
                this.f1866J = new ArrayList();
            }
            this.f1866J.add(interfaceC1778e);
        }
        return this;
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @NonNull
    @CheckResult
    /* renamed from: M, reason: merged with bridge method [inline-methods] */
    public C1558h<TranscodeType> mo766a(@NonNull AbstractC1774a<?> abstractC1774a) {
        Objects.requireNonNull(abstractC1774a, "Argument must not be null");
        return (C1558h) super.mo766a(abstractC1774a);
    }

    /* renamed from: N */
    public final InterfaceC1775b m753N(Object obj, InterfaceC1790i<TranscodeType> interfaceC1790i, @Nullable InterfaceC1778e<TranscodeType> interfaceC1778e, @Nullable InterfaceC1776c interfaceC1776c, AbstractC1560j<?, ? super TranscodeType> abstractC1560j, EnumC1556f enumC1556f, int i2, int i3, AbstractC1774a<?> abstractC1774a, Executor executor) {
        return m765Z(obj, interfaceC1790i, interfaceC1778e, abstractC1774a, null, abstractC1560j, enumC1556f, i2, i3, executor);
    }

    @Override // p005b.p143g.p144a.p166q.AbstractC1774a
    @CheckResult
    /* renamed from: O, reason: merged with bridge method [inline-methods] */
    public C1558h<TranscodeType> clone() {
        C1558h<TranscodeType> c1558h = (C1558h) super.clone();
        c1558h.f1864H = (AbstractC1560j<?, ? super TranscodeType>) c1558h.f1864H.m781a();
        return c1558h;
    }

    @NonNull
    /* renamed from: P */
    public <Y extends InterfaceC1790i<TranscodeType>> Y m755P(@NonNull Y y) {
        m756Q(y, null, this, C1802d.f2755a);
        return y;
    }

    /* renamed from: Q */
    public final <Y extends InterfaceC1790i<TranscodeType>> Y m756Q(@NonNull Y y, @Nullable InterfaceC1778e<TranscodeType> interfaceC1778e, AbstractC1774a<?> abstractC1774a, Executor executor) {
        Objects.requireNonNull(y, "Argument must not be null");
        if (!this.f1868L) {
            throw new IllegalArgumentException("You must call #load() before calling #into()");
        }
        InterfaceC1775b m753N = m753N(new Object(), y, interfaceC1778e, null, this.f1864H, abstractC1774a.f2659g, abstractC1774a.f2666n, abstractC1774a.f2665m, abstractC1774a, executor);
        InterfaceC1775b request = y.getRequest();
        C1781h c1781h = (C1781h) m753N;
        if (c1781h.m1116i(request)) {
            if (!(!abstractC1774a.f2664l && request.mo1102d())) {
                Objects.requireNonNull(request, "Argument must not be null");
                if (!request.isRunning()) {
                    request.mo1101c();
                }
                return y;
            }
        }
        this.f1861E.m772e(y);
        y.setRequest(m753N);
        ComponentCallbacks2C1559i componentCallbacks2C1559i = this.f1861E;
        synchronized (componentCallbacks2C1559i) {
            componentCallbacks2C1559i.f1878k.f2635c.add(y);
            C1760n c1760n = componentCallbacks2C1559i.f1876i;
            c1760n.f2632a.add(m753N);
            if (c1760n.f2634c) {
                c1781h.clear();
                Log.isLoggable("RequestTracker", 2);
                c1760n.f2633b.add(m753N);
            } else {
                c1781h.mo1101c();
            }
        }
        return y;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0066  */
    @androidx.annotation.NonNull
    /* renamed from: R */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p143g.p144a.p166q.p167i.AbstractC1791j<android.widget.ImageView, TranscodeType> m757R(@androidx.annotation.NonNull android.widget.ImageView r4) {
        /*
            r3 = this;
            p005b.p143g.p144a.p170s.C1807i.m1144a()
            java.lang.String r0 = "Argument must not be null"
            java.util.Objects.requireNonNull(r4, r0)
            r0 = 2048(0x800, float:2.87E-42)
            boolean r0 = r3.m1091p(r0)
            if (r0 != 0) goto L4e
            boolean r0 = r3.f2669q
            if (r0 == 0) goto L4e
            android.widget.ImageView$ScaleType r0 = r4.getScaleType()
            if (r0 == 0) goto L4e
            int[] r0 = p005b.p143g.p144a.C1558h.a.f1869a
            android.widget.ImageView$ScaleType r1 = r4.getScaleType()
            int r1 = r1.ordinal()
            r0 = r0[r1]
            switch(r0) {
                case 1: goto L45;
                case 2: goto L3c;
                case 3: goto L33;
                case 4: goto L33;
                case 5: goto L33;
                case 6: goto L2a;
                default: goto L29;
            }
        L29:
            goto L4e
        L2a:
            b.g.a.q.a r0 = r3.clone()
            b.g.a.q.a r0 = r0.mo1094u()
            goto L4f
        L33:
            b.g.a.q.a r0 = r3.clone()
            b.g.a.q.a r0 = r0.mo1095v()
            goto L4f
        L3c:
            b.g.a.q.a r0 = r3.clone()
            b.g.a.q.a r0 = r0.mo1094u()
            goto L4f
        L45:
            b.g.a.q.a r0 = r3.clone()
            b.g.a.q.a r0 = r0.mo1093t()
            goto L4f
        L4e:
            r0 = r3
        L4f:
            b.g.a.e r1 = r3.f1863G
            java.lang.Class<TranscodeType> r2 = r3.f1862F
            b.g.a.q.i.g r1 = r1.f1837d
            java.util.Objects.requireNonNull(r1)
            java.lang.Class<android.graphics.Bitmap> r1 = android.graphics.Bitmap.class
            boolean r1 = r1.equals(r2)
            if (r1 == 0) goto L66
            b.g.a.q.i.b r1 = new b.g.a.q.i.b
            r1.<init>(r4)
            goto L73
        L66:
            java.lang.Class<android.graphics.drawable.Drawable> r1 = android.graphics.drawable.Drawable.class
            boolean r1 = r1.isAssignableFrom(r2)
            if (r1 == 0) goto L7a
            b.g.a.q.i.e r1 = new b.g.a.q.i.e
            r1.<init>(r4)
        L73:
            r4 = 0
            java.util.concurrent.Executor r2 = p005b.p143g.p144a.p170s.C1802d.f2755a
            r3.m756Q(r1, r4, r0, r2)
            return r1
        L7a:
            java.lang.IllegalArgumentException r4 = new java.lang.IllegalArgumentException
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "Unhandled class: "
            r0.append(r1)
            r0.append(r2)
            java.lang.String r1 = ", try .as*(Class).transcode(ResourceTranscoder)"
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            r4.<init>(r0)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.C1558h.m757R(android.widget.ImageView):b.g.a.q.i.j");
    }

    @NonNull
    @CheckResult
    /* renamed from: S */
    public C1558h<TranscodeType> mo758S(@Nullable InterfaceC1778e<TranscodeType> interfaceC1778e) {
        this.f1866J = null;
        return mo751L(interfaceC1778e);
    }

    @NonNull
    @CheckResult
    /* renamed from: T */
    public C1558h<TranscodeType> mo759T(@Nullable Drawable drawable) {
        this.f1865I = drawable;
        this.f1868L = true;
        return mo766a(C1779f.m1110L(AbstractC1643k.f2223b));
    }

    @NonNull
    @CheckResult
    /* renamed from: U */
    public C1558h<TranscodeType> mo760U(@Nullable File file) {
        this.f1865I = file;
        this.f1868L = true;
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: V */
    public C1558h<TranscodeType> mo761V(@Nullable @DrawableRes @RawRes Integer num) {
        PackageInfo packageInfo;
        this.f1865I = num;
        this.f1868L = true;
        Context context = this.f1860D;
        int i2 = C1795a.f2738b;
        ConcurrentMap<String, InterfaceC1579k> concurrentMap = C1796b.f2741a;
        String packageName = context.getPackageName();
        InterfaceC1579k interfaceC1579k = C1796b.f2741a.get(packageName);
        if (interfaceC1579k == null) {
            try {
                packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            } catch (PackageManager.NameNotFoundException unused) {
                context.getPackageName();
                packageInfo = null;
            }
            C1798d c1798d = new C1798d(packageInfo != null ? String.valueOf(packageInfo.versionCode) : UUID.randomUUID().toString());
            interfaceC1579k = C1796b.f2741a.putIfAbsent(packageName, c1798d);
            if (interfaceC1579k == null) {
                interfaceC1579k = c1798d;
            }
        }
        return mo766a(new C1779f().mo1073C(new C1795a(context.getResources().getConfiguration().uiMode & 48, interfaceC1579k)));
    }

    @NonNull
    @CheckResult
    /* renamed from: W */
    public C1558h<TranscodeType> mo762W(@Nullable Object obj) {
        this.f1865I = obj;
        this.f1868L = true;
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: X */
    public C1558h<TranscodeType> mo763X(@Nullable String str) {
        this.f1865I = str;
        this.f1868L = true;
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: Y */
    public C1558h<TranscodeType> mo764Y(@Nullable byte[] bArr) {
        this.f1865I = bArr;
        this.f1868L = true;
        C1558h<TranscodeType> mo766a = !m1091p(4) ? mo766a(C1779f.m1110L(AbstractC1643k.f2223b)) : this;
        if (mo766a.m1091p(256)) {
            return mo766a;
        }
        if (C1779f.f2688D == null) {
            C1779f.f2688D = new C1779f().mo1075E(true).mo1082c();
        }
        return mo766a.mo766a(C1779f.f2688D);
    }

    /* renamed from: Z */
    public final InterfaceC1775b m765Z(Object obj, InterfaceC1790i<TranscodeType> interfaceC1790i, InterfaceC1778e<TranscodeType> interfaceC1778e, AbstractC1774a<?> abstractC1774a, InterfaceC1776c interfaceC1776c, AbstractC1560j<?, ? super TranscodeType> abstractC1560j, EnumC1556f enumC1556f, int i2, int i3, Executor executor) {
        Context context = this.f1860D;
        C1555e c1555e = this.f1863G;
        Object obj2 = this.f1865I;
        Class<TranscodeType> cls = this.f1862F;
        List<InterfaceC1778e<TranscodeType>> list = this.f1866J;
        C1644l c1644l = c1555e.f1841h;
        Objects.requireNonNull(abstractC1560j);
        return new C1781h(context, c1555e, obj, obj2, cls, abstractC1774a, i2, i3, enumC1556f, interfaceC1790i, interfaceC1778e, list, interfaceC1776c, c1644l, C1792a.f2737b, executor);
    }
}
