package com.facebook.react.modules.network;

import B2.t;
import B2.u;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class m implements a {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private B2.n f7152c;

    @Override // com.facebook.react.modules.network.a
    public void a() {
        this.f7152c = null;
    }

    @Override // B2.n
    public void b(u uVar, List list) {
        t2.j.f(uVar, "url");
        t2.j.f(list, "cookies");
        B2.n nVar = this.f7152c;
        if (nVar != null) {
            nVar.b(uVar, list);
        }
    }

    @Override // B2.n
    public List c(u uVar) {
        t2.j.f(uVar, "url");
        B2.n nVar = this.f7152c;
        if (nVar == null) {
            return AbstractC0586n.g();
        }
        List<B2.m> listC = nVar.c(uVar);
        ArrayList arrayList = new ArrayList();
        for (B2.m mVar : listC) {
            try {
                new t.a().a(mVar.a(), mVar.b());
                arrayList.add(mVar);
            } catch (IllegalArgumentException unused) {
            }
        }
        return arrayList;
    }

    @Override // com.facebook.react.modules.network.a
    public void d(B2.n nVar) {
        t2.j.f(nVar, "cookieJar");
        this.f7152c = nVar;
    }
}
