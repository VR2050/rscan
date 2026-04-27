package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class dg extends df {
    private final boolean c;
    private int d;

    public dg(av avVar, boolean z, da daVar) {
        super(avVar, daVar);
        this.c = z;
    }

    public void a(int i) {
        this.d = i;
    }

    @Override // io.openinstall.sdk.cs
    protected String k() {
        return "install";
    }

    @Override // io.openinstall.sdk.df
    protected void o() {
        if (this.c) {
            h().b(k());
        } else {
            h().a(k());
        }
    }

    @Override // io.openinstall.sdk.df
    protected cy q() {
        return cy.a(c().a());
    }

    @Override // io.openinstall.sdk.df
    protected int r() {
        int i = this.d;
        if (i > 0) {
            return i;
        }
        return 10;
    }
}
