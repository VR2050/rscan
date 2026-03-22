package p005b.p199l.p258c.p260c0.p261a0;

import java.io.Reader;
import java.util.Iterator;
import java.util.Map;
import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.C2482l;
import p005b.p199l.p258c.C2487q;
import p005b.p199l.p258c.C2488r;
import p005b.p199l.p258c.C2490t;
import p005b.p199l.p258c.p260c0.C2461s;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.c0.a0.e */
/* loaded from: classes2.dex */
public final class C2425e extends C2472a {

    /* renamed from: t */
    public static final Object f6468t;

    /* renamed from: u */
    public Object[] f6469u;

    /* renamed from: v */
    public int f6470v;

    /* renamed from: w */
    public String[] f6471w;

    /* renamed from: x */
    public int[] f6472x;

    /* renamed from: b.l.c.c0.a0.e$a */
    public static class a extends Reader {
        @Override // java.io.Reader, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            throw new AssertionError();
        }

        @Override // java.io.Reader
        public int read(char[] cArr, int i2, int i3) {
            throw new AssertionError();
        }
    }

    static {
        new a();
        f6468t = new Object();
    }

    /* renamed from: C */
    private String m2769C() {
        StringBuilder m586H = C1499a.m586H(" at path ");
        m586H.append(getPath());
        return m586H.toString();
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: D */
    public boolean mo2770D() {
        m2781g0(EnumC2473b.BOOLEAN);
        boolean m2861b = ((C2490t) m2783i0()).m2861b();
        int i2 = this.f6470v;
        if (i2 > 0) {
            int[] iArr = this.f6472x;
            int i3 = i2 - 1;
            iArr[i3] = iArr[i3] + 1;
        }
        return m2861b;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: E */
    public double mo2771E() {
        EnumC2473b mo2777Z = mo2777Z();
        EnumC2473b enumC2473b = EnumC2473b.NUMBER;
        if (mo2777Z != enumC2473b && mo2777Z != EnumC2473b.STRING) {
            throw new IllegalStateException("Expected " + enumC2473b + " but was " + mo2777Z + m2769C());
        }
        C2490t c2490t = (C2490t) m2782h0();
        double doubleValue = c2490t.f6698b instanceof Number ? c2490t.m2862c().doubleValue() : Double.parseDouble(c2490t.m2863d());
        if (!this.f6641f && (Double.isNaN(doubleValue) || Double.isInfinite(doubleValue))) {
            throw new NumberFormatException("JSON forbids NaN and infinities: " + doubleValue);
        }
        m2783i0();
        int i2 = this.f6470v;
        if (i2 > 0) {
            int[] iArr = this.f6472x;
            int i3 = i2 - 1;
            iArr[i3] = iArr[i3] + 1;
        }
        return doubleValue;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: I */
    public int mo2772I() {
        EnumC2473b mo2777Z = mo2777Z();
        EnumC2473b enumC2473b = EnumC2473b.NUMBER;
        if (mo2777Z != enumC2473b && mo2777Z != EnumC2473b.STRING) {
            throw new IllegalStateException("Expected " + enumC2473b + " but was " + mo2777Z + m2769C());
        }
        C2490t c2490t = (C2490t) m2782h0();
        int intValue = c2490t.f6698b instanceof Number ? c2490t.m2862c().intValue() : Integer.parseInt(c2490t.m2863d());
        m2783i0();
        int i2 = this.f6470v;
        if (i2 > 0) {
            int[] iArr = this.f6472x;
            int i3 = i2 - 1;
            iArr[i3] = iArr[i3] + 1;
        }
        return intValue;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: P */
    public long mo2773P() {
        EnumC2473b mo2777Z = mo2777Z();
        EnumC2473b enumC2473b = EnumC2473b.NUMBER;
        if (mo2777Z != enumC2473b && mo2777Z != EnumC2473b.STRING) {
            throw new IllegalStateException("Expected " + enumC2473b + " but was " + mo2777Z + m2769C());
        }
        C2490t c2490t = (C2490t) m2782h0();
        long longValue = c2490t.f6698b instanceof Number ? c2490t.m2862c().longValue() : Long.parseLong(c2490t.m2863d());
        m2783i0();
        int i2 = this.f6470v;
        if (i2 > 0) {
            int[] iArr = this.f6472x;
            int i3 = i2 - 1;
            iArr[i3] = iArr[i3] + 1;
        }
        return longValue;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: S */
    public String mo2774S() {
        m2781g0(EnumC2473b.NAME);
        Map.Entry entry = (Map.Entry) ((Iterator) m2782h0()).next();
        String str = (String) entry.getKey();
        this.f6471w[this.f6470v - 1] = str;
        m2784j0(entry.getValue());
        return str;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: V */
    public void mo2775V() {
        m2781g0(EnumC2473b.NULL);
        m2783i0();
        int i2 = this.f6470v;
        if (i2 > 0) {
            int[] iArr = this.f6472x;
            int i3 = i2 - 1;
            iArr[i3] = iArr[i3] + 1;
        }
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: X */
    public String mo2776X() {
        EnumC2473b mo2777Z = mo2777Z();
        EnumC2473b enumC2473b = EnumC2473b.STRING;
        if (mo2777Z == enumC2473b || mo2777Z == EnumC2473b.NUMBER) {
            String m2863d = ((C2490t) m2783i0()).m2863d();
            int i2 = this.f6470v;
            if (i2 > 0) {
                int[] iArr = this.f6472x;
                int i3 = i2 - 1;
                iArr[i3] = iArr[i3] + 1;
            }
            return m2863d;
        }
        throw new IllegalStateException("Expected " + enumC2473b + " but was " + mo2777Z + m2769C());
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: Z */
    public EnumC2473b mo2777Z() {
        if (this.f6470v == 0) {
            return EnumC2473b.END_DOCUMENT;
        }
        Object m2782h0 = m2782h0();
        if (m2782h0 instanceof Iterator) {
            boolean z = this.f6469u[this.f6470v - 2] instanceof C2488r;
            Iterator it = (Iterator) m2782h0;
            if (!it.hasNext()) {
                return z ? EnumC2473b.END_OBJECT : EnumC2473b.END_ARRAY;
            }
            if (z) {
                return EnumC2473b.NAME;
            }
            m2784j0(it.next());
            return mo2777Z();
        }
        if (m2782h0 instanceof C2488r) {
            return EnumC2473b.BEGIN_OBJECT;
        }
        if (m2782h0 instanceof C2482l) {
            return EnumC2473b.BEGIN_ARRAY;
        }
        if (!(m2782h0 instanceof C2490t)) {
            if (m2782h0 instanceof C2487q) {
                return EnumC2473b.NULL;
            }
            if (m2782h0 == f6468t) {
                throw new IllegalStateException("JsonReader is closed");
            }
            throw new AssertionError();
        }
        Object obj = ((C2490t) m2782h0).f6698b;
        if (obj instanceof String) {
            return EnumC2473b.STRING;
        }
        if (obj instanceof Boolean) {
            return EnumC2473b.BOOLEAN;
        }
        if (obj instanceof Number) {
            return EnumC2473b.NUMBER;
        }
        throw new AssertionError();
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: b */
    public void mo2778b() {
        m2781g0(EnumC2473b.BEGIN_ARRAY);
        m2784j0(((C2482l) m2782h0()).iterator());
        this.f6472x[this.f6470v - 1] = 0;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f6469u = new Object[]{f6468t};
        this.f6470v = 1;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: d */
    public void mo2779d() {
        m2781g0(EnumC2473b.BEGIN_OBJECT);
        m2784j0(new C2461s.b.a((C2461s.b) ((C2488r) m2782h0()).f6696a.entrySet()));
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: e0 */
    public void mo2780e0() {
        if (mo2777Z() == EnumC2473b.NAME) {
            mo2774S();
            this.f6471w[this.f6470v - 2] = "null";
        } else {
            m2783i0();
            int i2 = this.f6470v;
            if (i2 > 0) {
                this.f6471w[i2 - 1] = "null";
            }
        }
        int i3 = this.f6470v;
        if (i3 > 0) {
            int[] iArr = this.f6472x;
            int i4 = i3 - 1;
            iArr[i4] = iArr[i4] + 1;
        }
    }

    /* renamed from: g0 */
    public final void m2781g0(EnumC2473b enumC2473b) {
        if (mo2777Z() == enumC2473b) {
            return;
        }
        throw new IllegalStateException("Expected " + enumC2473b + " but was " + mo2777Z() + m2769C());
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    public String getPath() {
        StringBuilder m584F = C1499a.m584F(Typography.dollar);
        int i2 = 0;
        while (i2 < this.f6470v) {
            Object[] objArr = this.f6469u;
            if (objArr[i2] instanceof C2482l) {
                i2++;
                if (objArr[i2] instanceof Iterator) {
                    m584F.append('[');
                    m584F.append(this.f6472x[i2]);
                    m584F.append(']');
                }
            } else if (objArr[i2] instanceof C2488r) {
                i2++;
                if (objArr[i2] instanceof Iterator) {
                    m584F.append('.');
                    String[] strArr = this.f6471w;
                    if (strArr[i2] != null) {
                        m584F.append(strArr[i2]);
                    }
                }
            }
            i2++;
        }
        return m584F.toString();
    }

    /* renamed from: h0 */
    public final Object m2782h0() {
        return this.f6469u[this.f6470v - 1];
    }

    /* renamed from: i0 */
    public final Object m2783i0() {
        Object[] objArr = this.f6469u;
        int i2 = this.f6470v - 1;
        this.f6470v = i2;
        Object obj = objArr[i2];
        objArr[i2] = null;
        return obj;
    }

    /* renamed from: j0 */
    public final void m2784j0(Object obj) {
        int i2 = this.f6470v;
        Object[] objArr = this.f6469u;
        if (i2 == objArr.length) {
            Object[] objArr2 = new Object[i2 * 2];
            int[] iArr = new int[i2 * 2];
            String[] strArr = new String[i2 * 2];
            System.arraycopy(objArr, 0, objArr2, 0, i2);
            System.arraycopy(this.f6472x, 0, iArr, 0, this.f6470v);
            System.arraycopy(this.f6471w, 0, strArr, 0, this.f6470v);
            this.f6469u = objArr2;
            this.f6472x = iArr;
            this.f6471w = strArr;
        }
        Object[] objArr3 = this.f6469u;
        int i3 = this.f6470v;
        this.f6470v = i3 + 1;
        objArr3[i3] = obj;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: o */
    public void mo2785o() {
        m2781g0(EnumC2473b.END_ARRAY);
        m2783i0();
        m2783i0();
        int i2 = this.f6470v;
        if (i2 > 0) {
            int[] iArr = this.f6472x;
            int i3 = i2 - 1;
            iArr[i3] = iArr[i3] + 1;
        }
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: q */
    public void mo2786q() {
        m2781g0(EnumC2473b.END_OBJECT);
        m2783i0();
        m2783i0();
        int i2 = this.f6470v;
        if (i2 > 0) {
            int[] iArr = this.f6472x;
            int i3 = i2 - 1;
            iArr[i3] = iArr[i3] + 1;
        }
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    /* renamed from: t */
    public boolean mo2787t() {
        EnumC2473b mo2777Z = mo2777Z();
        return (mo2777Z == EnumC2473b.END_OBJECT || mo2777Z == EnumC2473b.END_ARRAY) ? false : true;
    }

    @Override // p005b.p199l.p258c.p265e0.C2472a
    public String toString() {
        return C2425e.class.getSimpleName();
    }
}
