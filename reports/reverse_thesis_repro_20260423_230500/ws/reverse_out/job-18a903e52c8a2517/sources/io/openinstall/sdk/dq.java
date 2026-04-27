package io.openinstall.sdk;

import android.text.TextUtils;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class dq extends dp {
    public dq(av avVar) {
        super(avVar, null);
    }

    private Map<String, Object> p() {
        Map<String, Object> mapSynchronizedMap = Collections.synchronizedMap(new HashMap());
        mapSynchronizedMap.put("ntrh", f().h());
        mapSynchronizedMap.put("regh", f().i());
        mapSynchronizedMap.put("mrth", f().j());
        mapSynchronizedMap.put("krtn", f().k());
        String strF = as.a().f();
        if (!TextUtils.isEmpty(strF)) {
            mapSynchronizedMap.put("gpde", strF);
        }
        return mapSynchronizedMap;
    }

    @Override // io.openinstall.sdk.cs
    protected String k() {
        return "check_dialog";
    }

    @Override // io.openinstall.sdk.dp
    protected cy o() {
        cr crVarE = e().e(p());
        if (!crVarE.a()) {
            return cy.a(crVarE);
        }
        bd bdVarA = bd.a(crVarE);
        if (bdVarA != null) {
            as.a().a(bdVarA);
            this.a.d().b(bdVarA.a());
        }
        return cy.a();
    }
}
