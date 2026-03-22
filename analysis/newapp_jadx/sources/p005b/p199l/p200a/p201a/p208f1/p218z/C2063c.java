package p005b.p199l.p200a.p201a.p208f1.p218z;

import androidx.annotation.Nullable;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2036g;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.z.c */
/* loaded from: classes.dex */
public final class C2063c extends AbstractC2064d {

    /* renamed from: b */
    public long f4267b;

    public C2063c() {
        super(new C2036g());
        this.f4267b = -9223372036854775807L;
    }

    @Nullable
    /* renamed from: d */
    public static Object m1648d(C2360t c2360t, int i2) {
        if (i2 == 0) {
            return Double.valueOf(Double.longBitsToDouble(c2360t.m2579k()));
        }
        if (i2 == 1) {
            return Boolean.valueOf(c2360t.m2585q() == 1);
        }
        if (i2 == 2) {
            return m1650f(c2360t);
        }
        if (i2 != 3) {
            if (i2 == 8) {
                return m1649e(c2360t);
            }
            if (i2 != 10) {
                if (i2 != 11) {
                    return null;
                }
                Date date = new Date((long) Double.valueOf(Double.longBitsToDouble(c2360t.m2579k())).doubleValue());
                c2360t.m2568D(2);
                return date;
            }
            int m2588t = c2360t.m2588t();
            ArrayList arrayList = new ArrayList(m2588t);
            for (int i3 = 0; i3 < m2588t; i3++) {
                Object m1648d = m1648d(c2360t, c2360t.m2585q());
                if (m1648d != null) {
                    arrayList.add(m1648d);
                }
            }
            return arrayList;
        }
        HashMap hashMap = new HashMap();
        while (true) {
            String m1650f = m1650f(c2360t);
            int m2585q = c2360t.m2585q();
            if (m2585q == 9) {
                return hashMap;
            }
            Object m1648d2 = m1648d(c2360t, m2585q);
            if (m1648d2 != null) {
                hashMap.put(m1650f, m1648d2);
            }
        }
    }

    /* renamed from: e */
    public static HashMap<String, Object> m1649e(C2360t c2360t) {
        int m2588t = c2360t.m2588t();
        HashMap<String, Object> hashMap = new HashMap<>(m2588t);
        for (int i2 = 0; i2 < m2588t; i2++) {
            String m1650f = m1650f(c2360t);
            Object m1648d = m1648d(c2360t, c2360t.m2585q());
            if (m1648d != null) {
                hashMap.put(m1650f, m1648d);
            }
        }
        return hashMap;
    }

    /* renamed from: f */
    public static String m1650f(C2360t c2360t) {
        int m2590v = c2360t.m2590v();
        int i2 = c2360t.f6134b;
        c2360t.m2568D(m2590v);
        return new String(c2360t.f6133a, i2, m2590v);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p218z.AbstractC2064d
    /* renamed from: b */
    public boolean mo1644b(C2360t c2360t) {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p218z.AbstractC2064d
    /* renamed from: c */
    public boolean mo1645c(C2360t c2360t, long j2) {
        if (c2360t.m2585q() != 2) {
            throw new C2205l0();
        }
        if (!"onMetaData".equals(m1650f(c2360t)) || c2360t.m2585q() != 8) {
            return false;
        }
        HashMap<String, Object> m1649e = m1649e(c2360t);
        if (m1649e.containsKey("duration")) {
            double doubleValue = ((Double) m1649e.get("duration")).doubleValue();
            if (doubleValue > ShadowDrawableWrapper.COS_45) {
                this.f4267b = (long) (doubleValue * 1000000.0d);
            }
        }
        return false;
    }
}
