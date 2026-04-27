package io.openinstall.sdk;

import android.net.Uri;
import io.openinstall.sdk.cy;
import java.util.HashMap;

/* JADX INFO: loaded from: classes3.dex */
public class dl extends dj {
    private final Uri c;

    public dl(av avVar, Uri uri) {
        super(avVar, null);
        this.c = uri;
    }

    @Override // io.openinstall.sdk.cs
    protected String k() {
        return "stat_wake";
    }

    @Override // io.openinstall.sdk.dj
    protected cy o() {
        if (!d().b()) {
            if (ec.a) {
                ec.a("wakeupStatsEnabled is disable", new Object[0]);
            }
            return cy.a.REQUEST_ERROR.a("wakeupStatsEnabled is disable");
        }
        HashMap map = new HashMap();
        Uri uri = this.c;
        if (uri != null) {
            map.put("qpxs", uri.toString());
        }
        return cy.a(e().c(map));
    }
}
