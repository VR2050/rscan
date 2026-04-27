package io.openinstall.sdk;

import android.content.Context;
import io.openinstall.sdk.cy;
import java.io.File;
import java.io.IOException;

/* JADX INFO: loaded from: classes3.dex */
public class dr extends dp {
    public dr(av avVar, da daVar) {
        super(avVar, daVar);
    }

    @Override // io.openinstall.sdk.cs
    protected String k() {
        return "apk";
    }

    @Override // io.openinstall.sdk.dp
    protected cy o() {
        Context contextC = as.a().c();
        String str = contextC.getApplicationInfo().sourceDir;
        String str2 = contextC.getFilesDir() + File.separator + contextC.getPackageName() + ".apk";
        try {
            cc.a((byte[]) null, new File(str), new File(str2));
            return cy.a(str2);
        } catch (IOException e) {
            if (ec.a) {
                e.printStackTrace();
            }
            return cy.a.REQUEST_FAIL.a(e.getMessage());
        }
    }
}
