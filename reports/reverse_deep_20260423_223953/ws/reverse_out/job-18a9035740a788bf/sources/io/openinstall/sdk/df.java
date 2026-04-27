package io.openinstall.sdk;

import io.openinstall.sdk.cy;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* JADX INFO: loaded from: classes3.dex */
public abstract class df extends cs implements Callable<cy> {
    public df(av avVar, da daVar) {
        super(avVar, daVar);
    }

    @Override // io.openinstall.sdk.cs
    protected cy n() {
        Future futureSubmit = i().submit(this);
        try {
            return (cy) futureSubmit.get(r(), TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            futureSubmit.cancel(true);
            return cy.a.REQUEST_TIMEOUT.a();
        } catch (Exception e2) {
            return cy.a.REQUEST_FAIL.a(e2.getMessage());
        }
    }

    protected void o() {
        h().a(k());
    }

    @Override // java.util.concurrent.Callable
    /* JADX INFO: renamed from: p, reason: merged with bridge method [inline-methods] */
    public cy call() {
        o();
        b().a(k(), r());
        if (!b().c()) {
            return cy.a.REQUEST_TIMEOUT.a();
        }
        if (b().b()) {
            return q();
        }
        return cy.a.INIT_ERROR.a(c().b());
    }

    protected abstract cy q();

    protected abstract int r();
}
