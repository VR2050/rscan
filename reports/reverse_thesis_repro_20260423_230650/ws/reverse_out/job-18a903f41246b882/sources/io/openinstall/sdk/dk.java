package io.openinstall.sdk;

import java.util.HashMap;

/* JADX INFO: loaded from: classes3.dex */
public class dk extends dj {
    private final bh c;

    public dk(av avVar, bh bhVar, da daVar) {
        super(avVar, daVar);
        this.c = bhVar;
    }

    @Override // io.openinstall.sdk.cs
    protected String k() {
        return "stat_share";
    }

    @Override // io.openinstall.sdk.dj
    protected cy o() {
        HashMap map = new HashMap();
        map.put("iewb", this.c.a());
        map.put("ncbd", this.c.b());
        cr crVarD = e().d(map);
        if (!crVarD.a()) {
            crVarD = e().d(map);
        }
        return cy.a(crVarD);
    }
}
