package p005b.p113c0.p114a.p116h.p120j;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import p005b.p113c0.p114a.p115g.C1419e;
import p005b.p113c0.p114a.p116h.p121k.C1444b;
import p005b.p113c0.p114a.p116h.p121k.C1446d;
import p005b.p113c0.p114a.p124i.EnumC1456b;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p130l.InterfaceC1498j;
import p005b.p327w.p328a.C2822b;

/* renamed from: b.c0.a.h.j.b */
/* loaded from: classes2.dex */
public abstract class AbstractC1438b implements InterfaceC1437a, InterfaceC1498j {
    /* renamed from: c */
    public static C1444b m500c(List<C1444b> list, EnumC1456b enumC1456b) {
        for (C1444b c1444b : list) {
            if (c1444b.f1397b.f1398a.contains(enumC1456b)) {
                return c1444b;
            }
        }
        return null;
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1437a
    @Nullable
    /* renamed from: a */
    public InterfaceC1442f mo498a(@NonNull InterfaceC1457c interfaceC1457c) {
        List<C1446d.b> m509c = C1446d.m509c(interfaceC1457c.getPath());
        List<C1444b> m502e = m502e(m509c);
        if (((ArrayList) m502e).isEmpty()) {
            m502e = m501d(m509c);
        }
        EnumC1456b mo523d = interfaceC1457c.mo523d();
        C1444b m500c = m500c(m502e, mo523d);
        if (mo523d.equals(EnumC1456b.OPTIONS) && m500c == null) {
            return new C1441e(interfaceC1457c, m502e, ((C2822b) this).f7666f);
        }
        if (m500c == null) {
            return null;
        }
        return ((C2822b) this).f7666f.get(m500c);
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1437a
    /* renamed from: b */
    public boolean mo499b(@NonNull InterfaceC1457c interfaceC1457c) {
        List<C1446d.b> m509c = C1446d.m509c(interfaceC1457c.getPath());
        List<C1444b> m502e = m502e(m509c);
        if (((ArrayList) m502e).isEmpty()) {
            m502e = m501d(m509c);
        }
        if (m502e.isEmpty()) {
            return false;
        }
        EnumC1456b mo523d = interfaceC1457c.mo523d();
        if (mo523d.equals(EnumC1456b.OPTIONS) || m500c(m502e, mo523d) != null) {
            return true;
        }
        C1419e c1419e = new C1419e(mo523d);
        ArrayList arrayList = new ArrayList();
        Iterator<C1444b> it = m502e.iterator();
        while (it.hasNext()) {
            arrayList.addAll(it.next().f1397b.f1398a);
        }
        c1419e.f1375e = arrayList;
        throw c1419e;
    }

    /* renamed from: d */
    public final List<C1444b> m501d(List<C1446d.b> list) {
        ArrayList arrayList = new ArrayList();
        for (C1444b c1444b : ((C2822b) this).f7666f.keySet()) {
            Iterator<C1446d.a> it = c1444b.f1396a.f1399e.iterator();
            while (it.hasNext()) {
                List<C1446d.b> list2 = it.next().f1400a;
                boolean z = false;
                if (list.size() == list2.size()) {
                    int i2 = 0;
                    while (true) {
                        if (i2 >= list2.size()) {
                            z = true;
                            break;
                        }
                        C1446d.b bVar = list2.get(i2);
                        if (!bVar.equals(list.get(i2)) && !bVar.f1402b) {
                            break;
                        }
                        i2++;
                    }
                }
                if (z) {
                    arrayList.add(c1444b);
                }
            }
        }
        return arrayList;
    }

    /* renamed from: e */
    public final List<C1444b> m502e(List<C1446d.b> list) {
        ArrayList arrayList = new ArrayList();
        for (C1444b c1444b : ((C2822b) this).f7666f.keySet()) {
            Iterator<C1446d.a> it = c1444b.f1396a.f1399e.iterator();
            while (it.hasNext()) {
                List<C1446d.b> list2 = it.next().f1400a;
                boolean z = false;
                if (list.size() == list2.size() && C1446d.m508b(list2).equals(C1446d.m508b(list))) {
                    z = true;
                }
                if (z) {
                    arrayList.add(c1444b);
                }
            }
        }
        return arrayList;
    }
}
