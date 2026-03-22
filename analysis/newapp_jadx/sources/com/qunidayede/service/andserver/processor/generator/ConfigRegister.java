package com.qunidayede.service.andserver.processor.generator;

import android.content.Context;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import p005b.p113c0.p114a.C1412d;
import p005b.p113c0.p114a.p116h.p118h.C1433a;
import p005b.p113c0.p114a.p116h.p118h.InterfaceC1435c;
import p005b.p113c0.p114a.p116h.p123m.AbstractC1454d;
import p005b.p113c0.p114a.p128j.InterfaceC1483a;
import p005b.p113c0.p114a.p128j.InterfaceC1484b;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p328a.p329f.C2826a;

/* loaded from: classes2.dex */
public final class ConfigRegister implements InterfaceC1483a {
    private Map<String, InterfaceC1435c> mMap;

    public ConfigRegister() {
        HashMap hashMap = new HashMap();
        this.mMap = hashMap;
        hashMap.put("default", new C2826a());
    }

    @Override // p005b.p113c0.p114a.p128j.InterfaceC1483a
    public void onRegister(Context context, String str, InterfaceC1484b interfaceC1484b) {
        InterfaceC1435c interfaceC1435c = this.mMap.get(str);
        if (interfaceC1435c == null) {
            interfaceC1435c = this.mMap.get("default");
        }
        if (interfaceC1435c != null) {
            C1433a c1433a = new C1433a();
            interfaceC1435c.mo497a(context, c1433a);
            List<AbstractC1454d> list = c1433a.f1381b;
            if (list != null && !list.isEmpty()) {
                for (AbstractC1454d abstractC1454d : list) {
                    C1412d c1412d = (C1412d) interfaceC1484b;
                    Objects.requireNonNull(c1412d);
                    C2354n.m2474f1(abstractC1454d, "The adapter cannot be null.");
                    if (!c1412d.f1371f.contains(abstractC1454d)) {
                        c1412d.f1371f.add(abstractC1454d);
                    }
                }
            }
            ((C1412d) interfaceC1484b).f1370e = c1433a.f1380a;
        }
    }
}
