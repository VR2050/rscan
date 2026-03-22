package p005b.p143g.p144a.p147m.p150t.p151c0;

import android.graphics.Bitmap;
import android.os.Build;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.VisibleForTesting;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p170s.C1807i;

@RequiresApi(19)
/* renamed from: b.g.a.m.t.c0.m */
/* loaded from: classes.dex */
public class C1623m implements InterfaceC1621k {

    /* renamed from: a */
    public static final Bitmap.Config[] f2084a;

    /* renamed from: b */
    public static final Bitmap.Config[] f2085b;

    /* renamed from: c */
    public static final Bitmap.Config[] f2086c;

    /* renamed from: d */
    public static final Bitmap.Config[] f2087d;

    /* renamed from: e */
    public static final Bitmap.Config[] f2088e;

    /* renamed from: f */
    public final c f2089f = new c();

    /* renamed from: g */
    public final C1617g<b, Bitmap> f2090g = new C1617g<>();

    /* renamed from: h */
    public final Map<Bitmap.Config, NavigableMap<Integer, Integer>> f2091h = new HashMap();

    /* renamed from: b.g.a.m.t.c0.m$a */
    public static /* synthetic */ class a {

        /* renamed from: a */
        public static final /* synthetic */ int[] f2092a;

        static {
            int[] iArr = new int[Bitmap.Config.values().length];
            f2092a = iArr;
            try {
                iArr[Bitmap.Config.ARGB_8888.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f2092a[Bitmap.Config.RGB_565.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f2092a[Bitmap.Config.ARGB_4444.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f2092a[Bitmap.Config.ALPHA_8.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.t.c0.m$b */
    public static final class b implements InterfaceC1622l {

        /* renamed from: a */
        public final c f2093a;

        /* renamed from: b */
        public int f2094b;

        /* renamed from: c */
        public Bitmap.Config f2095c;

        public b(c cVar) {
            this.f2093a = cVar;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1622l
        /* renamed from: a */
        public void mo881a() {
            this.f2093a.m866c(this);
        }

        public boolean equals(Object obj) {
            if (!(obj instanceof b)) {
                return false;
            }
            b bVar = (b) obj;
            return this.f2094b == bVar.f2094b && C1807i.m1145b(this.f2095c, bVar.f2095c);
        }

        public int hashCode() {
            int i2 = this.f2094b * 31;
            Bitmap.Config config = this.f2095c;
            return i2 + (config != null ? config.hashCode() : 0);
        }

        public String toString() {
            return C1623m.m887c(this.f2094b, this.f2095c);
        }
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.t.c0.m$c */
    public static class c extends AbstractC1613c<b> {
        @Override // p005b.p143g.p144a.p147m.p150t.p151c0.AbstractC1613c
        /* renamed from: a */
        public b mo864a() {
            return new b(this);
        }

        /* renamed from: d */
        public b m893d(int i2, Bitmap.Config config) {
            b m865b = m865b();
            m865b.f2094b = i2;
            m865b.f2095c = config;
            return m865b;
        }
    }

    static {
        Bitmap.Config[] configArr = {Bitmap.Config.ARGB_8888, null};
        if (Build.VERSION.SDK_INT >= 26) {
            configArr = (Bitmap.Config[]) Arrays.copyOf(configArr, 3);
            configArr[configArr.length - 1] = Bitmap.Config.RGBA_F16;
        }
        f2084a = configArr;
        f2085b = configArr;
        f2086c = new Bitmap.Config[]{Bitmap.Config.RGB_565};
        f2087d = new Bitmap.Config[]{Bitmap.Config.ARGB_4444};
        f2088e = new Bitmap.Config[]{Bitmap.Config.ALPHA_8};
    }

    /* renamed from: c */
    public static String m887c(int i2, Bitmap.Config config) {
        return "[" + i2 + "](" + config + ChineseToPinyinResource.Field.RIGHT_BRACKET;
    }

    /* renamed from: a */
    public final void m888a(Integer num, Bitmap bitmap) {
        NavigableMap<Integer, Integer> m890d = m890d(bitmap.getConfig());
        Integer num2 = (Integer) m890d.get(num);
        if (num2 != null) {
            if (num2.intValue() == 1) {
                m890d.remove(num);
                return;
            } else {
                m890d.put(num, Integer.valueOf(num2.intValue() - 1));
                return;
            }
        }
        throw new NullPointerException("Tried to decrement empty size, size: " + num + ", removed: " + m891e(bitmap) + ", this: " + this);
    }

    @Nullable
    /* renamed from: b */
    public Bitmap m889b(int i2, int i3, Bitmap.Config config) {
        Bitmap.Config[] configArr;
        int m1146c = C1807i.m1146c(i2, i3, config);
        b m865b = this.f2089f.m865b();
        m865b.f2094b = m1146c;
        m865b.f2095c = config;
        int i4 = 0;
        if (Build.VERSION.SDK_INT < 26 || !Bitmap.Config.RGBA_F16.equals(config)) {
            int i5 = a.f2092a[config.ordinal()];
            configArr = i5 != 1 ? i5 != 2 ? i5 != 3 ? i5 != 4 ? new Bitmap.Config[]{config} : f2088e : f2087d : f2086c : f2084a;
        } else {
            configArr = f2085b;
        }
        int length = configArr.length;
        while (true) {
            if (i4 >= length) {
                break;
            }
            Bitmap.Config config2 = configArr[i4];
            Integer ceilingKey = m890d(config2).ceilingKey(Integer.valueOf(m1146c));
            if (ceilingKey == null || ceilingKey.intValue() > m1146c * 8) {
                i4++;
            } else if (ceilingKey.intValue() != m1146c || (config2 != null ? !config2.equals(config) : config != null)) {
                this.f2089f.m866c(m865b);
                m865b = this.f2089f.m893d(ceilingKey.intValue(), config2);
            }
        }
        Bitmap m872a = this.f2090g.m872a(m865b);
        if (m872a != null) {
            m888a(Integer.valueOf(m865b.f2094b), m872a);
            m872a.reconfigure(i2, i3, config);
        }
        return m872a;
    }

    /* renamed from: d */
    public final NavigableMap<Integer, Integer> m890d(Bitmap.Config config) {
        NavigableMap<Integer, Integer> navigableMap = this.f2091h.get(config);
        if (navigableMap != null) {
            return navigableMap;
        }
        TreeMap treeMap = new TreeMap();
        this.f2091h.put(config, treeMap);
        return treeMap;
    }

    /* renamed from: e */
    public String m891e(Bitmap bitmap) {
        return m887c(C1807i.m1147d(bitmap), bitmap.getConfig());
    }

    /* renamed from: f */
    public void m892f(Bitmap bitmap) {
        b m893d = this.f2089f.m893d(C1807i.m1147d(bitmap), bitmap.getConfig());
        this.f2090g.m873b(m893d, bitmap);
        NavigableMap<Integer, Integer> m890d = m890d(bitmap.getConfig());
        Integer num = (Integer) m890d.get(Integer.valueOf(m893d.f2094b));
        m890d.put(Integer.valueOf(m893d.f2094b), Integer.valueOf(num != null ? 1 + num.intValue() : 1));
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("SizeConfigStrategy{groupedMap=");
        m586H.append(this.f2090g);
        m586H.append(", sortedSizes=(");
        for (Map.Entry<Bitmap.Config, NavigableMap<Integer, Integer>> entry : this.f2091h.entrySet()) {
            m586H.append(entry.getKey());
            m586H.append('[');
            m586H.append(entry.getValue());
            m586H.append("], ");
        }
        if (!this.f2091h.isEmpty()) {
            m586H.replace(m586H.length() - 2, m586H.length(), "");
        }
        m586H.append(")}");
        return m586H.toString();
    }
}
