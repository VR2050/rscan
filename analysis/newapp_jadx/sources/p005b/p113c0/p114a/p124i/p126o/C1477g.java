package p005b.p113c0.p114a.p124i.p126o;

import android.text.TextUtils;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import p005b.p113c0.p114a.p115g.C1418d;
import p005b.p113c0.p114a.p115g.C1420f;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1460f;
import p005b.p113c0.p114a.p130l.C1494f;
import p005b.p113c0.p114a.p130l.C1495g;
import p005b.p113c0.p114a.p130l.InterfaceC1497i;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p478a.p479a.AbstractC4769e;
import p476m.p477a.p478a.p479a.C4768d;
import p476m.p477a.p478a.p479a.C4770f;
import p476m.p477a.p478a.p479a.InterfaceC4765a;
import p476m.p477a.p478a.p479a.p480l.C4777b;
import p476m.p477a.p478a.p483b.C4784a;

/* renamed from: b.c0.a.i.o.g */
/* loaded from: classes2.dex */
public class C1477g implements InterfaceC1474d {

    /* renamed from: a */
    public C4777b f1465a;

    /* renamed from: b */
    public C4768d f1466b;

    /* renamed from: b.c0.a.i.o.g$a */
    public static class a {

        /* renamed from: a */
        public final InterfaceC1497i<String, InterfaceC1472b> f1467a;

        /* renamed from: b */
        public final InterfaceC1497i<String, String> f1468b;

        /* renamed from: c */
        public final Map<String, String> f1469c;

        public a(InterfaceC1497i<String, InterfaceC1472b> interfaceC1497i, InterfaceC1497i<String, String> interfaceC1497i2, Map<String, String> map) {
            this.f1467a = interfaceC1497i;
            this.f1468b = interfaceC1497i2;
            this.f1469c = map;
        }
    }

    public C1477g() {
        C4777b c4777b = new C4777b();
        this.f1465a = c4777b;
        this.f1466b = new C4768d(c4777b);
    }

    /* renamed from: a */
    public void m553a(InterfaceC1473c interfaceC1473c) {
        if (interfaceC1473c != null) {
            try {
                Iterator it = ((C1494f) interfaceC1473c.mo552g()).values().iterator();
                while (it.hasNext()) {
                    for (InterfaceC1472b interfaceC1472b : (List) it.next()) {
                        if (interfaceC1472b instanceof C1475e) {
                            ((C1475e) interfaceC1472b).f1460c.mo5428a();
                        }
                    }
                }
            } catch (Throwable unused) {
            }
        }
    }

    /* renamed from: b */
    public a m554b(List<InterfaceC4765a> list, String str) {
        String mo5429b;
        Charset m574d;
        C1494f c1494f = new C1494f();
        C1494f c1494f2 = new C1494f();
        HashMap hashMap = new HashMap();
        for (InterfaceC4765a interfaceC4765a : list) {
            if (interfaceC4765a.mo5431d()) {
                String contentType = interfaceC4765a.getContentType();
                String name = (TextUtils.isEmpty(contentType) || (m574d = C1495g.m568k(contentType).m574d()) == null) ? str : m574d.name();
                if (name != null) {
                    try {
                        mo5429b = interfaceC4765a.getString(name);
                    } catch (UnsupportedEncodingException unused) {
                        mo5429b = interfaceC4765a.mo5429b();
                    }
                } else {
                    mo5429b = interfaceC4765a.mo5429b();
                }
                List list2 = (List) c1494f2.get(interfaceC4765a.mo5430c());
                if (list2 == null) {
                    LinkedList linkedList = new LinkedList();
                    linkedList.add(mo5429b);
                    c1494f2.put(interfaceC4765a.mo5430c(), linkedList);
                } else {
                    list2.add(mo5429b);
                }
                hashMap.put(interfaceC4765a.mo5430c(), interfaceC4765a.getContentType());
            } else {
                c1494f.m566a(interfaceC4765a.mo5430c(), new C1475e(interfaceC4765a));
            }
        }
        return new a(c1494f, c1494f2, hashMap);
    }

    /* renamed from: c */
    public InterfaceC1473c m555c(InterfaceC1457c interfaceC1457c) {
        String name;
        if (interfaceC1457c instanceof InterfaceC1473c) {
            return (InterfaceC1473c) interfaceC1457c;
        }
        C1495g contentType = interfaceC1457c.getContentType();
        if (contentType == null) {
            name = C4784a.m5463a("utf-8").name();
        } else {
            Charset m574d = contentType.m574d();
            if (m574d == null) {
                m574d = C4784a.m5463a("utf-8");
            }
            name = m574d.name();
        }
        C4768d c4768d = this.f1466b;
        if (!name.equalsIgnoreCase(c4768d.f12184c)) {
            c4768d = new C4768d(this.f1465a);
            C4768d c4768d2 = this.f1466b;
            c4768d.f12182a = c4768d2.f12182a;
            c4768d.f12183b = c4768d2.f12183b;
            c4768d.f12184c = name;
        }
        try {
            InterfaceC1460f mo526h = interfaceC1457c.mo526h();
            C2354n.m2474f1(mo526h, "The body cannot be null.");
            a m554b = m554b(c4768d.m5435d(new C1471a(mo526h)), name);
            return new C1476f(interfaceC1457c, m554b.f1467a, m554b.f1468b, m554b.f1469c);
        } catch (AbstractC4769e.b e2) {
            throw new C1418d(c4768d.f12183b, e2);
        } catch (AbstractC4769e.g e3) {
            throw new C1418d(c4768d.f12182a, e3);
        } catch (C4770f e4) {
            throw new C1420f("Failed to parse multipart servlet request.", e4);
        }
    }
}
