package io.openinstall.sdk;

import android.net.Uri;
import android.util.Pair;
import io.openinstall.sdk.cy;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class dh extends df {
    private final Uri c;

    public dh(av avVar, Uri uri, da daVar) {
        super(avVar, daVar);
        this.c = uri;
    }

    private cy s() {
        List<String> pathSegments = this.c.getPathSegments();
        if (pathSegments == null || pathSegments.size() <= 0) {
            return cy.a.INVALID_DATA.a();
        }
        int iIndexOf = pathSegments.indexOf("applinks");
        if (pathSegments.size() < iIndexOf + 3) {
            return cy.a.INVALID_DATA.a();
        }
        int i = iIndexOf + 1;
        if (pathSegments.get(i).equalsIgnoreCase("c")) {
            return cy.a(dw.b(pathSegments.get(iIndexOf + 2)));
        }
        if (!pathSegments.get(i).equalsIgnoreCase("h")) {
            return cy.a.INVALID_DATA.a();
        }
        HashMap map = new HashMap();
        map.put("wpxk", this.c.toString());
        cr crVarB = e().b(map);
        if (!crVarB.a()) {
            crVarB = e().b(map);
        }
        return cy.a(crVarB);
    }

    private cy t() {
        HashMap map = new HashMap();
        LinkedBlockingQueue linkedBlockingQueue = new LinkedBlockingQueue(1);
        j().execute(new di(this, linkedBlockingQueue));
        try {
            Pair pair = (Pair) linkedBlockingQueue.poll(3L, TimeUnit.SECONDS);
            map.put(pair.first, pair.second);
            h().a(k());
        } catch (InterruptedException e) {
        }
        cr crVarB = e().b(map);
        if (!crVarB.a()) {
            crVarB = e().b(map);
        }
        return cy.a(crVarB);
    }

    @Override // io.openinstall.sdk.cs
    protected String k() {
        return "wakeup";
    }

    @Override // io.openinstall.sdk.df
    protected cy q() {
        return this.c == null ? t() : s();
    }

    @Override // io.openinstall.sdk.df
    protected int r() {
        return 6;
    }
}
