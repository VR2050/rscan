package com.qunidayede.service.andserver.processor.generator;

import android.content.Context;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import p005b.p113c0.p114a.C1412d;
import p005b.p113c0.p114a.p116h.p120j.InterfaceC1437a;
import p005b.p113c0.p114a.p128j.InterfaceC1483a;
import p005b.p113c0.p114a.p128j.InterfaceC1484b;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p328a.C2822b;

/* loaded from: classes2.dex */
public final class AdapterRegister implements InterfaceC1483a {
    private Map<String, List<InterfaceC1437a>> mMap = new HashMap();

    public AdapterRegister() {
        ArrayList arrayList = new ArrayList();
        arrayList.add(new C2822b());
        this.mMap.put("default", arrayList);
    }

    @Override // p005b.p113c0.p114a.p128j.InterfaceC1483a
    public void onRegister(Context context, String str, InterfaceC1484b interfaceC1484b) {
        List<InterfaceC1437a> list = this.mMap.get(str);
        if (list == null) {
            list = new ArrayList();
        }
        List<InterfaceC1437a> list2 = this.mMap.get("default");
        if (list2 != null && !list2.isEmpty()) {
            list.addAll(list2);
        }
        if (list.isEmpty()) {
            return;
        }
        for (InterfaceC1437a interfaceC1437a : list) {
            C1412d c1412d = (C1412d) interfaceC1484b;
            Objects.requireNonNull(c1412d);
            C2354n.m2474f1(interfaceC1437a, "The adapter cannot be null.");
            if (!c1412d.f1371f.contains(interfaceC1437a)) {
                c1412d.f1371f.add(interfaceC1437a);
            }
        }
    }
}
