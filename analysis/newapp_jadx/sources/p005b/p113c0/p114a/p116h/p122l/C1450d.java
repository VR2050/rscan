package p005b.p113c0.p114a.p116h.p122l;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p113c0.p114a.C1411c;
import p005b.p113c0.p114a.p115g.C1421g;
import p005b.p113c0.p114a.p115g.C1424j;
import p005b.p113c0.p114a.p116h.p117g.C1432b;
import p005b.p113c0.p114a.p124i.C1466l;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;
import p005b.p113c0.p114a.p124i.InterfaceC1461g;
import p005b.p113c0.p114a.p124i.InterfaceC1463i;
import p005b.p113c0.p114a.p130l.C1495g;
import p005b.p113c0.p114a.p130l.InterfaceC1498j;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.c0.a.h.l.d */
/* loaded from: classes2.dex */
public class C1450d implements InterfaceC1498j {
    /* renamed from: a */
    public void m513a(@Nullable InterfaceC1449c interfaceC1449c, @NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d) {
        if (interfaceC1449c == null) {
            return;
        }
        Object mo512b = interfaceC1449c.mo512b();
        if (interfaceC1449c.mo511a()) {
            if (mo512b instanceof InterfaceC1463i) {
                ((C1466l) interfaceC1458d).m539a((InterfaceC1463i) mo512b);
                return;
            }
            if (mo512b == null) {
                ((C1466l) interfaceC1458d).f1437b.mo5527d(new C1466l.b(new C1432b("", C1495g.f1510k), null));
                return;
            } else {
                if (!(mo512b instanceof String)) {
                    ((C1466l) interfaceC1458d).f1437b.mo5527d(new C1466l.b(new C1432b(mo512b.toString(), C1495g.f1510k), null));
                    return;
                }
                String obj = mo512b.toString();
                Object mo518a = interfaceC1457c.mo518a("http.response.Produce");
                ((C1466l) interfaceC1458d).f1437b.mo5527d(new C1466l.b(new C1432b(obj, mo518a instanceof C1495g ? (C1495g) mo518a : null), null));
                return;
            }
        }
        if (!(mo512b instanceof CharSequence)) {
            throw new C1424j(String.format("The return value of [%s] is not supported", mo512b));
        }
        String obj2 = mo512b.toString();
        if (TextUtils.isEmpty(obj2)) {
            return;
        }
        if (obj2.matches("redirect:(.)*")) {
            C1466l c1466l = (C1466l) interfaceC1458d;
            c1466l.f1437b.mo5529i(302);
            if (obj2.length() >= 9) {
                c1466l.f1437b.mo5520o("Location", obj2.substring(9));
                return;
            }
            return;
        }
        if (obj2.matches("forward:(.)*")) {
            String substring = obj2.substring(8);
            InterfaceC1461g mo525f = interfaceC1457c.mo525f(substring);
            if (mo525f == null) {
                throw new C1421g(substring);
            }
            ((C1411c) mo525f).f1365a.m488d(interfaceC1457c, interfaceC1458d);
            return;
        }
        if (!obj2.matches(InterfaceC1498j.f1517c)) {
            throw new C1421g(obj2);
        }
        String m637w = C1499a.m637w(obj2, ".html");
        InterfaceC1461g mo525f2 = interfaceC1457c.mo525f(m637w);
        if (mo525f2 == null) {
            throw new C1421g(m637w);
        }
        ((C1411c) mo525f2).f1365a.m488d(interfaceC1457c, interfaceC1458d);
    }
}
