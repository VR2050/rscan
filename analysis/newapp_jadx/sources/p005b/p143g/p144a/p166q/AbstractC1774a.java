package p005b.p143g.p144a.p166q;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import androidx.annotation.CheckResult;
import androidx.annotation.DrawableRes;
import androidx.annotation.FloatRange;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import com.bumptech.glide.util.CachedHashCodeArrayMap;
import java.util.Map;
import java.util.Objects;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1580l;
import p005b.p143g.p144a.p147m.C1581m;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1570b;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.AbstractC1643k;
import p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m;
import p005b.p143g.p144a.p147m.p156v.p157c.C1704i;
import p005b.p143g.p144a.p147m.p156v.p157c.C1705j;
import p005b.p143g.p144a.p147m.p156v.p157c.C1706k;
import p005b.p143g.p144a.p147m.p156v.p157c.C1709n;
import p005b.p143g.p144a.p147m.p156v.p157c.C1711p;
import p005b.p143g.p144a.p147m.p156v.p157c.C1713r;
import p005b.p143g.p144a.p147m.p156v.p161g.C1735e;
import p005b.p143g.p144a.p147m.p156v.p161g.C1738h;
import p005b.p143g.p144a.p166q.AbstractC1774a;
import p005b.p143g.p144a.p169r.C1797c;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.q.a */
/* loaded from: classes.dex */
public abstract class AbstractC1774a<T extends AbstractC1774a<T>> implements Cloneable {

    /* renamed from: A */
    public boolean f2653A;

    /* renamed from: B */
    public boolean f2654B;

    /* renamed from: C */
    public boolean f2655C;

    /* renamed from: c */
    public int f2656c;

    /* renamed from: h */
    @Nullable
    public Drawable f2660h;

    /* renamed from: i */
    public int f2661i;

    /* renamed from: j */
    @Nullable
    public Drawable f2662j;

    /* renamed from: k */
    public int f2663k;

    /* renamed from: o */
    @NonNull
    public InterfaceC1579k f2667o;

    /* renamed from: p */
    public boolean f2668p;

    /* renamed from: q */
    public boolean f2669q;

    /* renamed from: r */
    @Nullable
    public Drawable f2670r;

    /* renamed from: s */
    public int f2671s;

    /* renamed from: t */
    @NonNull
    public C1582n f2672t;

    /* renamed from: u */
    @NonNull
    public Map<Class<?>, InterfaceC1586r<?>> f2673u;

    /* renamed from: v */
    @NonNull
    public Class<?> f2674v;

    /* renamed from: w */
    public boolean f2675w;

    /* renamed from: x */
    @Nullable
    public Resources.Theme f2676x;

    /* renamed from: y */
    public boolean f2677y;

    /* renamed from: z */
    public boolean f2678z;

    /* renamed from: e */
    public float f2657e = 1.0f;

    /* renamed from: f */
    @NonNull
    public AbstractC1643k f2658f = AbstractC1643k.f2225d;

    /* renamed from: g */
    @NonNull
    public EnumC1556f f2659g = EnumC1556f.NORMAL;

    /* renamed from: l */
    public boolean f2664l = true;

    /* renamed from: m */
    public int f2665m = -1;

    /* renamed from: n */
    public int f2666n = -1;

    public AbstractC1774a() {
        C1797c c1797c = C1797c.f2742b;
        this.f2667o = C1797c.f2742b;
        this.f2669q = true;
        this.f2672t = new C1582n();
        this.f2673u = new CachedHashCodeArrayMap();
        this.f2674v = Object.class;
        this.f2654B = true;
    }

    /* renamed from: r */
    public static boolean m1070r(int i2, int i3) {
        return (i2 & i3) != 0;
    }

    @NonNull
    /* renamed from: A */
    public final T m1071A() {
        if (this.f2675w) {
            throw new IllegalStateException("You cannot modify locked T, consider clone()");
        }
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: B */
    public <Y> T mo1072B(@NonNull C1581m<Y> c1581m, @NonNull Y y) {
        if (this.f2677y) {
            return (T) clone().mo1072B(c1581m, y);
        }
        Objects.requireNonNull(c1581m, "Argument must not be null");
        Objects.requireNonNull(y, "Argument must not be null");
        this.f2672t.f1995b.put(c1581m, y);
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: C */
    public T mo1073C(@NonNull InterfaceC1579k interfaceC1579k) {
        if (this.f2677y) {
            return (T) clone().mo1073C(interfaceC1579k);
        }
        Objects.requireNonNull(interfaceC1579k, "Argument must not be null");
        this.f2667o = interfaceC1579k;
        this.f2656c |= 1024;
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: D */
    public T mo1074D(@FloatRange(from = 0.0d, m110to = 1.0d) float f2) {
        if (this.f2677y) {
            return (T) clone().mo1074D(f2);
        }
        if (f2 < 0.0f || f2 > 1.0f) {
            throw new IllegalArgumentException("sizeMultiplier must be between 0 and 1");
        }
        this.f2657e = f2;
        this.f2656c |= 2;
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: E */
    public T mo1075E(boolean z) {
        if (this.f2677y) {
            return (T) clone().mo1075E(true);
        }
        this.f2664l = !z;
        this.f2656c |= 256;
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: F */
    public T mo1076F(@NonNull InterfaceC1586r<Bitmap> interfaceC1586r) {
        return m1077G(interfaceC1586r, true);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @NonNull
    /* renamed from: G */
    public T m1077G(@NonNull InterfaceC1586r<Bitmap> interfaceC1586r, boolean z) {
        if (this.f2677y) {
            return (T) clone().m1077G(interfaceC1586r, z);
        }
        C1711p c1711p = new C1711p(interfaceC1586r, z);
        m1079I(Bitmap.class, interfaceC1586r, z);
        m1079I(Drawable.class, c1711p, z);
        m1079I(BitmapDrawable.class, c1711p, z);
        m1079I(GifDrawable.class, new C1735e(interfaceC1586r), z);
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: H */
    public final T m1078H(@NonNull AbstractC1708m abstractC1708m, @NonNull InterfaceC1586r<Bitmap> interfaceC1586r) {
        if (this.f2677y) {
            return (T) clone().m1078H(abstractC1708m, interfaceC1586r);
        }
        mo1087j(abstractC1708m);
        return mo1076F(interfaceC1586r);
    }

    @NonNull
    /* renamed from: I */
    public <Y> T m1079I(@NonNull Class<Y> cls, @NonNull InterfaceC1586r<Y> interfaceC1586r, boolean z) {
        if (this.f2677y) {
            return (T) clone().m1079I(cls, interfaceC1586r, z);
        }
        Objects.requireNonNull(cls, "Argument must not be null");
        Objects.requireNonNull(interfaceC1586r, "Argument must not be null");
        this.f2673u.put(cls, interfaceC1586r);
        int i2 = this.f2656c | 2048;
        this.f2656c = i2;
        this.f2669q = true;
        int i3 = i2 | 65536;
        this.f2656c = i3;
        this.f2654B = false;
        if (z) {
            this.f2656c = i3 | 131072;
            this.f2668p = true;
        }
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: J */
    public T mo1080J(@NonNull InterfaceC1586r<Bitmap>... interfaceC1586rArr) {
        if (interfaceC1586rArr.length > 1) {
            return m1077G(new C1580l(interfaceC1586rArr), true);
        }
        if (interfaceC1586rArr.length == 1) {
            return mo1076F(interfaceC1586rArr[0]);
        }
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: K */
    public T mo1081K(boolean z) {
        if (this.f2677y) {
            return (T) clone().mo1081K(z);
        }
        this.f2655C = z;
        this.f2656c |= 1048576;
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: a */
    public T mo766a(@NonNull AbstractC1774a<?> abstractC1774a) {
        if (this.f2677y) {
            return (T) clone().mo766a(abstractC1774a);
        }
        if (m1070r(abstractC1774a.f2656c, 2)) {
            this.f2657e = abstractC1774a.f2657e;
        }
        if (m1070r(abstractC1774a.f2656c, 262144)) {
            this.f2678z = abstractC1774a.f2678z;
        }
        if (m1070r(abstractC1774a.f2656c, 1048576)) {
            this.f2655C = abstractC1774a.f2655C;
        }
        if (m1070r(abstractC1774a.f2656c, 4)) {
            this.f2658f = abstractC1774a.f2658f;
        }
        if (m1070r(abstractC1774a.f2656c, 8)) {
            this.f2659g = abstractC1774a.f2659g;
        }
        if (m1070r(abstractC1774a.f2656c, 16)) {
            this.f2660h = abstractC1774a.f2660h;
            this.f2661i = 0;
            this.f2656c &= -33;
        }
        if (m1070r(abstractC1774a.f2656c, 32)) {
            this.f2661i = abstractC1774a.f2661i;
            this.f2660h = null;
            this.f2656c &= -17;
        }
        if (m1070r(abstractC1774a.f2656c, 64)) {
            this.f2662j = abstractC1774a.f2662j;
            this.f2663k = 0;
            this.f2656c &= -129;
        }
        if (m1070r(abstractC1774a.f2656c, 128)) {
            this.f2663k = abstractC1774a.f2663k;
            this.f2662j = null;
            this.f2656c &= -65;
        }
        if (m1070r(abstractC1774a.f2656c, 256)) {
            this.f2664l = abstractC1774a.f2664l;
        }
        if (m1070r(abstractC1774a.f2656c, 512)) {
            this.f2666n = abstractC1774a.f2666n;
            this.f2665m = abstractC1774a.f2665m;
        }
        if (m1070r(abstractC1774a.f2656c, 1024)) {
            this.f2667o = abstractC1774a.f2667o;
        }
        if (m1070r(abstractC1774a.f2656c, 4096)) {
            this.f2674v = abstractC1774a.f2674v;
        }
        if (m1070r(abstractC1774a.f2656c, 8192)) {
            this.f2670r = abstractC1774a.f2670r;
            this.f2671s = 0;
            this.f2656c &= -16385;
        }
        if (m1070r(abstractC1774a.f2656c, 16384)) {
            this.f2671s = abstractC1774a.f2671s;
            this.f2670r = null;
            this.f2656c &= -8193;
        }
        if (m1070r(abstractC1774a.f2656c, 32768)) {
            this.f2676x = abstractC1774a.f2676x;
        }
        if (m1070r(abstractC1774a.f2656c, 65536)) {
            this.f2669q = abstractC1774a.f2669q;
        }
        if (m1070r(abstractC1774a.f2656c, 131072)) {
            this.f2668p = abstractC1774a.f2668p;
        }
        if (m1070r(abstractC1774a.f2656c, 2048)) {
            this.f2673u.putAll(abstractC1774a.f2673u);
            this.f2654B = abstractC1774a.f2654B;
        }
        if (m1070r(abstractC1774a.f2656c, 524288)) {
            this.f2653A = abstractC1774a.f2653A;
        }
        if (!this.f2669q) {
            this.f2673u.clear();
            int i2 = this.f2656c & (-2049);
            this.f2656c = i2;
            this.f2668p = false;
            this.f2656c = i2 & (-131073);
            this.f2654B = true;
        }
        this.f2656c |= abstractC1774a.f2656c;
        this.f2672t.m828b(abstractC1774a.f2672t);
        m1071A();
        return this;
    }

    @NonNull
    /* renamed from: c */
    public T mo1082c() {
        if (this.f2675w && !this.f2677y) {
            throw new IllegalStateException("You cannot auto lock an already locked options object, try clone() first");
        }
        this.f2677y = true;
        return mo1092s();
    }

    @NonNull
    @CheckResult
    /* renamed from: d */
    public T mo1083d() {
        return m1078H(AbstractC1708m.f2501c, new C1704i());
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof AbstractC1774a)) {
            return false;
        }
        AbstractC1774a abstractC1774a = (AbstractC1774a) obj;
        return Float.compare(abstractC1774a.f2657e, this.f2657e) == 0 && this.f2661i == abstractC1774a.f2661i && C1807i.m1145b(this.f2660h, abstractC1774a.f2660h) && this.f2663k == abstractC1774a.f2663k && C1807i.m1145b(this.f2662j, abstractC1774a.f2662j) && this.f2671s == abstractC1774a.f2671s && C1807i.m1145b(this.f2670r, abstractC1774a.f2670r) && this.f2664l == abstractC1774a.f2664l && this.f2665m == abstractC1774a.f2665m && this.f2666n == abstractC1774a.f2666n && this.f2668p == abstractC1774a.f2668p && this.f2669q == abstractC1774a.f2669q && this.f2678z == abstractC1774a.f2678z && this.f2653A == abstractC1774a.f2653A && this.f2658f.equals(abstractC1774a.f2658f) && this.f2659g == abstractC1774a.f2659g && this.f2672t.equals(abstractC1774a.f2672t) && this.f2673u.equals(abstractC1774a.f2673u) && this.f2674v.equals(abstractC1774a.f2674v) && C1807i.m1145b(this.f2667o, abstractC1774a.f2667o) && C1807i.m1145b(this.f2676x, abstractC1774a.f2676x);
    }

    @NonNull
    @CheckResult
    /* renamed from: f */
    public T mo1084f() {
        return m1078H(AbstractC1708m.f2500b, new C1706k());
    }

    @Override // 
    @CheckResult
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public T clone() {
        try {
            T t = (T) super.clone();
            C1582n c1582n = new C1582n();
            t.f2672t = c1582n;
            c1582n.m828b(this.f2672t);
            CachedHashCodeArrayMap cachedHashCodeArrayMap = new CachedHashCodeArrayMap();
            t.f2673u = cachedHashCodeArrayMap;
            cachedHashCodeArrayMap.putAll(this.f2673u);
            t.f2675w = false;
            t.f2677y = false;
            return t;
        } catch (CloneNotSupportedException e2) {
            throw new RuntimeException(e2);
        }
    }

    @NonNull
    @CheckResult
    /* renamed from: h */
    public T mo1085h(@NonNull Class<?> cls) {
        if (this.f2677y) {
            return (T) clone().mo1085h(cls);
        }
        Objects.requireNonNull(cls, "Argument must not be null");
        this.f2674v = cls;
        this.f2656c |= 4096;
        m1071A();
        return this;
    }

    public int hashCode() {
        float f2 = this.f2657e;
        char[] cArr = C1807i.f2767a;
        return C1807i.m1149f(this.f2676x, C1807i.m1149f(this.f2667o, C1807i.m1149f(this.f2674v, C1807i.m1149f(this.f2673u, C1807i.m1149f(this.f2672t, C1807i.m1149f(this.f2659g, C1807i.m1149f(this.f2658f, (((((((((((((C1807i.m1149f(this.f2670r, (C1807i.m1149f(this.f2662j, (C1807i.m1149f(this.f2660h, ((Float.floatToIntBits(f2) + 527) * 31) + this.f2661i) * 31) + this.f2663k) * 31) + this.f2671s) * 31) + (this.f2664l ? 1 : 0)) * 31) + this.f2665m) * 31) + this.f2666n) * 31) + (this.f2668p ? 1 : 0)) * 31) + (this.f2669q ? 1 : 0)) * 31) + (this.f2678z ? 1 : 0)) * 31) + (this.f2653A ? 1 : 0))))))));
    }

    @NonNull
    @CheckResult
    /* renamed from: i */
    public T mo1086i(@NonNull AbstractC1643k abstractC1643k) {
        if (this.f2677y) {
            return (T) clone().mo1086i(abstractC1643k);
        }
        Objects.requireNonNull(abstractC1643k, "Argument must not be null");
        this.f2658f = abstractC1643k;
        this.f2656c |= 4;
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: j */
    public T mo1087j(@NonNull AbstractC1708m abstractC1708m) {
        C1581m c1581m = AbstractC1708m.f2504f;
        Objects.requireNonNull(abstractC1708m, "Argument must not be null");
        return mo1072B(c1581m, abstractC1708m);
    }

    @NonNull
    @CheckResult
    /* renamed from: l */
    public T mo1088l(@DrawableRes int i2) {
        if (this.f2677y) {
            return (T) clone().mo1088l(i2);
        }
        this.f2661i = i2;
        int i3 = this.f2656c | 32;
        this.f2656c = i3;
        this.f2660h = null;
        this.f2656c = i3 & (-17);
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: m */
    public T mo1089m(@DrawableRes int i2) {
        if (this.f2677y) {
            return (T) clone().mo1089m(i2);
        }
        this.f2671s = i2;
        int i3 = this.f2656c | 16384;
        this.f2656c = i3;
        this.f2670r = null;
        this.f2656c = i3 & (-8193);
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: n */
    public T mo1090n(@NonNull EnumC1570b enumC1570b) {
        Objects.requireNonNull(enumC1570b, "Argument must not be null");
        return (T) mo1072B(C1709n.f2506a, enumC1570b).mo1072B(C1738h.f2591a, enumC1570b);
    }

    /* renamed from: p */
    public final boolean m1091p(int i2) {
        return m1070r(this.f2656c, i2);
    }

    @NonNull
    /* renamed from: s */
    public T mo1092s() {
        this.f2675w = true;
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: t */
    public T mo1093t() {
        return m1096w(AbstractC1708m.f2501c, new C1704i());
    }

    @NonNull
    @CheckResult
    /* renamed from: u */
    public T mo1094u() {
        T m1096w = m1096w(AbstractC1708m.f2500b, new C1705j());
        m1096w.f2654B = true;
        return m1096w;
    }

    @NonNull
    @CheckResult
    /* renamed from: v */
    public T mo1095v() {
        T m1096w = m1096w(AbstractC1708m.f2499a, new C1713r());
        m1096w.f2654B = true;
        return m1096w;
    }

    @NonNull
    /* renamed from: w */
    public final T m1096w(@NonNull AbstractC1708m abstractC1708m, @NonNull InterfaceC1586r<Bitmap> interfaceC1586r) {
        if (this.f2677y) {
            return (T) clone().m1096w(abstractC1708m, interfaceC1586r);
        }
        mo1087j(abstractC1708m);
        return m1077G(interfaceC1586r, false);
    }

    @NonNull
    @CheckResult
    /* renamed from: x */
    public T mo1097x(int i2, int i3) {
        if (this.f2677y) {
            return (T) clone().mo1097x(i2, i3);
        }
        this.f2666n = i2;
        this.f2665m = i3;
        this.f2656c |= 512;
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: y */
    public T mo1098y(@DrawableRes int i2) {
        if (this.f2677y) {
            return (T) clone().mo1098y(i2);
        }
        this.f2663k = i2;
        int i3 = this.f2656c | 128;
        this.f2656c = i3;
        this.f2662j = null;
        this.f2656c = i3 & (-65);
        m1071A();
        return this;
    }

    @NonNull
    @CheckResult
    /* renamed from: z */
    public T mo1099z(@NonNull EnumC1556f enumC1556f) {
        if (this.f2677y) {
            return (T) clone().mo1099z(enumC1556f);
        }
        Objects.requireNonNull(enumC1556f, "Argument must not be null");
        this.f2659g = enumC1556f;
        this.f2656c |= 8;
        m1071A();
        return this;
    }
}
