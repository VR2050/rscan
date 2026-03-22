package p476m.p496b.p500b.p503h;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Iterator;
import p476m.p496b.p500b.AbstractC4926a;
import p476m.p496b.p500b.C4928c;
import p476m.p496b.p500b.C4930e;
import p476m.p496b.p500b.p501f.InterfaceC4931a;
import p476m.p496b.p500b.p502g.InterfaceC4938a;

/* renamed from: m.b.b.h.a */
/* loaded from: classes3.dex */
public final class C4942a implements Cloneable {

    /* renamed from: c */
    public final InterfaceC4931a f12596c;

    /* renamed from: e */
    public final String f12597e;

    /* renamed from: f */
    public final C4930e[] f12598f;

    /* renamed from: g */
    public final String[] f12599g;

    /* renamed from: h */
    public final String[] f12600h;

    /* renamed from: i */
    public final String[] f12601i;

    /* renamed from: j */
    public final C4930e f12602j;

    /* renamed from: k */
    public final boolean f12603k;

    /* renamed from: l */
    public final C4946e f12604l;

    /* renamed from: m */
    public InterfaceC4938a<?, ?> f12605m;

    public C4942a(InterfaceC4931a interfaceC4931a, Class<? extends AbstractC4926a<?, ?>> cls) {
        this.f12596c = interfaceC4931a;
        try {
            this.f12597e = (String) cls.getField("TABLENAME").get(null);
            C4930e[] m5611a = m5611a(cls);
            this.f12598f = m5611a;
            this.f12599g = new String[m5611a.length];
            ArrayList arrayList = new ArrayList();
            ArrayList arrayList2 = new ArrayList();
            C4930e c4930e = null;
            for (int i2 = 0; i2 < m5611a.length; i2++) {
                C4930e c4930e2 = m5611a[i2];
                String str = c4930e2.f12584e;
                this.f12599g[i2] = str;
                if (c4930e2.f12583d) {
                    arrayList.add(str);
                    c4930e = c4930e2;
                } else {
                    arrayList2.add(str);
                }
            }
            this.f12601i = (String[]) arrayList2.toArray(new String[arrayList2.size()]);
            String[] strArr = (String[]) arrayList.toArray(new String[arrayList.size()]);
            this.f12600h = strArr;
            C4930e c4930e3 = strArr.length == 1 ? c4930e : null;
            this.f12602j = c4930e3;
            this.f12604l = new C4946e(interfaceC4931a, this.f12597e, this.f12599g, strArr);
            if (c4930e3 == null) {
                this.f12603k = false;
            } else {
                Class<?> cls2 = c4930e3.f12581b;
                this.f12603k = cls2.equals(Long.TYPE) || cls2.equals(Long.class) || cls2.equals(Integer.TYPE) || cls2.equals(Integer.class) || cls2.equals(Short.TYPE) || cls2.equals(Short.class) || cls2.equals(Byte.TYPE) || cls2.equals(Byte.class);
            }
        } catch (Exception e2) {
            throw new C4928c("Could not init DAOConfig", e2);
        }
    }

    /* renamed from: a */
    public static C4930e[] m5611a(Class<? extends AbstractC4926a<?, ?>> cls) {
        Field[] declaredFields = Class.forName(cls.getName() + "$Properties").getDeclaredFields();
        ArrayList arrayList = new ArrayList();
        for (Field field : declaredFields) {
            if ((field.getModifiers() & 9) == 9) {
                Object obj = field.get(null);
                if (obj instanceof C4930e) {
                    arrayList.add((C4930e) obj);
                }
            }
        }
        C4930e[] c4930eArr = new C4930e[arrayList.size()];
        Iterator it = arrayList.iterator();
        while (it.hasNext()) {
            C4930e c4930e = (C4930e) it.next();
            int i2 = c4930e.f12580a;
            if (c4930eArr[i2] != null) {
                throw new C4928c("Duplicate property ordinals");
            }
            c4930eArr[i2] = c4930e;
        }
        return c4930eArr;
    }

    public Object clone() {
        return new C4942a(this);
    }

    public C4942a(C4942a c4942a) {
        this.f12596c = c4942a.f12596c;
        this.f12597e = c4942a.f12597e;
        this.f12598f = c4942a.f12598f;
        this.f12599g = c4942a.f12599g;
        this.f12600h = c4942a.f12600h;
        this.f12601i = c4942a.f12601i;
        this.f12602j = c4942a.f12602j;
        this.f12604l = c4942a.f12604l;
        this.f12603k = c4942a.f12603k;
    }
}
