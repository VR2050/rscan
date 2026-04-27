package io.openinstall.sdk;

import io.openinstall.sdk.cy;

/* JADX INFO: loaded from: classes3.dex */
public abstract class dp extends cs {
    public dp(av avVar, da daVar) {
        super(avVar, daVar);
    }

    @Override // io.openinstall.sdk.cs
    protected cy n() {
        try {
            return o();
        } catch (Exception e) {
            return cy.a.REQUEST_FAIL.a(e.getMessage());
        }
    }

    protected abstract cy o();
}
