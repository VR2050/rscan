package io.openinstall.sdk;

import com.fm.openinstall.listener.AppInstallListener;
import com.fm.openinstall.model.AppData;
import com.fm.openinstall.model.Error;
import io.openinstall.sdk.cy;
import org.json.JSONException;

/* JADX INFO: loaded from: classes3.dex */
class c implements da {
    final /* synthetic */ AppInstallListener a;
    final /* synthetic */ a b;

    c(a aVar, AppInstallListener appInstallListener) {
        this.b = aVar;
        this.a = appInstallListener;
    }

    @Override // io.openinstall.sdk.da
    public void a(cy cyVar) {
        if (cyVar.c() != null) {
            if (ec.a) {
                ec.c("decodeInstall fail : %s", cyVar.c());
            }
            AppInstallListener appInstallListener = this.a;
            if (appInstallListener != null) {
                appInstallListener.onInstallFinish(null, Error.fromInner(cyVar.c()));
                return;
            }
            return;
        }
        if (ec.a) {
            ec.a("decodeInstall success : %s", cyVar.b());
        }
        try {
            AppData appDataA = this.b.a(cyVar.b());
            if (this.a != null) {
                this.a.onInstallFinish(appDataA, null);
            }
        } catch (JSONException e) {
            if (ec.a) {
                ec.c("decodeInstall error : %s", e.toString());
            }
            AppInstallListener appInstallListener2 = this.a;
            if (appInstallListener2 != null) {
                appInstallListener2.onInstallFinish(null, Error.fromInner(cy.a.REQUEST_EXCEPTION));
            }
        }
    }
}
