package io.openinstall.sdk;

import android.util.Pair;

/* JADX INFO: renamed from: io.openinstall.sdk.do, reason: invalid class name */
/* JADX INFO: loaded from: classes3.dex */
public class Cdo extends cs {
    private static final String[] c = {"1.2.4.8", "223.5.5.5", "8.8.8.8", "180.76.76.76", "119.29.29.29", "208.67.222.222", "114.114.114.114"};
    private final dn d;

    public Cdo(av avVar, dn dnVar) {
        super(avVar, null);
        this.d = dnVar;
    }

    private Pair<String, String> a(String str) {
        if (str == null || !(str.isEmpty() || str.equals("\"\""))) {
            return dm.b(str);
        }
        c().a(false);
        return Pair.create(null, null);
    }

    private String o() {
        dn dnVar = this.d;
        if (dnVar == null) {
            return null;
        }
        String strA = dnVar.a(a());
        if (c().h()) {
            return this.a.c().a(strA);
        }
        return null;
    }

    @Override // io.openinstall.sdk.cs
    protected String k() {
        return "dynamic";
    }

    @Override // io.openinstall.sdk.cs
    protected void m() {
        super.m();
        this.a.c().a();
    }

    @Override // io.openinstall.sdk.cs
    protected cy n() {
        Pair<String, String> pairA = a(o());
        this.a.c().a((String) pairA.first, (String) pairA.second);
        return cy.a();
    }
}
