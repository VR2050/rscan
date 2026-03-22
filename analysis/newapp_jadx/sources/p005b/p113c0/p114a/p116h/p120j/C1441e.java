package p005b.p113c0.p114a.p116h.p120j;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import p005b.p113c0.p114a.p115g.C1421g;
import p005b.p113c0.p114a.p116h.p117g.C1432b;
import p005b.p113c0.p114a.p116h.p119i.C1436a;
import p005b.p113c0.p114a.p116h.p121k.C1444b;
import p005b.p113c0.p114a.p116h.p122l.C1447a;
import p005b.p113c0.p114a.p116h.p122l.InterfaceC1449c;
import p005b.p113c0.p114a.p124i.C1466l;
import p005b.p113c0.p114a.p124i.EnumC1456b;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;
import p005b.p113c0.p114a.p130l.C1495g;

/* renamed from: b.c0.a.h.j.e */
/* loaded from: classes2.dex */
public class C1441e implements InterfaceC1440d {

    /* renamed from: e */
    public List<C1444b> f1392e;

    /* renamed from: f */
    public Map<C1444b, InterfaceC1442f> f1393f;

    /* renamed from: g */
    public C1444b f1394g;

    /* renamed from: h */
    public InterfaceC1440d f1395h;

    public C1441e(InterfaceC1457c interfaceC1457c, List<C1444b> list, Map<C1444b, InterfaceC1442f> map) {
        this.f1392e = list;
        this.f1393f = map;
        this.f1394g = list.get(0);
        String mo528j = interfaceC1457c.mo528j("Access-Control-Request-Method");
        if (!TextUtils.isEmpty(mo528j)) {
            C1444b m500c = AbstractC1438b.m500c(this.f1392e, EnumC1456b.m520b(mo528j));
            if (m500c != null) {
                this.f1394g = m500c;
            }
        }
        this.f1395h = (InterfaceC1440d) this.f1393f.get(this.f1394g);
    }

    /* renamed from: a */
    public final InterfaceC1449c m507a(InterfaceC1458d interfaceC1458d) {
        ((C1466l) interfaceC1458d).f1437b.mo5529i(403);
        ((C1466l) interfaceC1458d).f1437b.mo5520o("Allow", TextUtils.join(", ", EnumC1456b.values()));
        return new C1447a(new C1432b("Invalid CORS request.", C1495g.f1510k));
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1440d
    @Nullable
    /* renamed from: c */
    public C1436a mo505c() {
        return this.f1395h.mo505c();
    }

    @Override // p005b.p113c0.p114a.p116h.InterfaceC1428d
    /* renamed from: d */
    public long mo493d(@NonNull InterfaceC1457c interfaceC1457c) {
        return this.f1395h.mo493d(interfaceC1457c);
    }

    @Override // p005b.p113c0.p114a.p116h.InterfaceC1425a
    /* renamed from: e */
    public String mo490e(@NonNull InterfaceC1457c interfaceC1457c) {
        return this.f1395h.mo490e(interfaceC1457c);
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1442f
    /* renamed from: f */
    public InterfaceC1449c mo506f(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d) {
        if (TextUtils.isEmpty(interfaceC1457c.mo528j("Origin"))) {
            return m507a(interfaceC1458d);
        }
        String mo528j = interfaceC1457c.mo528j("Access-Control-Request-Method");
        if (TextUtils.isEmpty(mo528j)) {
            return m507a(interfaceC1458d);
        }
        C1444b m500c = AbstractC1438b.m500c(this.f1392e, EnumC1456b.m520b(mo528j));
        if (m500c == null) {
            return m507a(interfaceC1458d);
        }
        InterfaceC1440d interfaceC1440d = (InterfaceC1440d) this.f1393f.get(m500c);
        if (interfaceC1440d == null) {
            throw new C1421g();
        }
        if (interfaceC1440d.mo505c() == null) {
            return m507a(interfaceC1458d);
        }
        new ArrayList();
        throw null;
    }
}
