package io.openinstall.sdk;

import io.openinstall.sdk.cy;

/* JADX INFO: loaded from: classes3.dex */
public abstract class dj extends cs {
    public dj(av avVar, da daVar) {
        super(avVar, daVar);
    }

    @Override // io.openinstall.sdk.cs
    protected cy n() {
        cy cyVarO;
        try {
            b().a();
            if (!b().c()) {
                cyVarO = cy.a.REQUEST_TIMEOUT.a();
            } else if (b().b()) {
                cyVarO = o();
            } else {
                cyVarO = cy.a.INIT_ERROR.a(c().b());
            }
            return cyVarO;
        } catch (Exception e) {
            return cy.a.REQUEST_FAIL.a(e.getMessage());
        }
    }

    protected abstract cy o();
}
