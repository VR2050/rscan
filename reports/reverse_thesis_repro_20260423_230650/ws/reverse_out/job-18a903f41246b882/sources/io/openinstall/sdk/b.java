package io.openinstall.sdk;

import android.net.Uri;
import com.fm.openinstall.listener.AppWakeUpListener;
import com.fm.openinstall.model.AppData;
import com.fm.openinstall.model.Error;
import io.openinstall.sdk.cy;
import org.json.JSONException;

/* JADX INFO: loaded from: classes3.dex */
class b implements da {
    final /* synthetic */ AppWakeUpListener a;
    final /* synthetic */ Uri b;
    final /* synthetic */ a c;

    b(a aVar, AppWakeUpListener appWakeUpListener, Uri uri) {
        this.c = aVar;
        this.a = appWakeUpListener;
        this.b = uri;
    }

    @Override // io.openinstall.sdk.da
    public void a(cy cyVar) {
        if (cyVar.c() != null) {
            if (ec.a) {
                ec.c("decodeWakeUp fail : %s", cyVar.c());
            }
            AppWakeUpListener appWakeUpListener = this.a;
            if (appWakeUpListener != null) {
                appWakeUpListener.onWakeUpFinish(null, Error.fromInner(cyVar.c()));
                return;
            }
            return;
        }
        String strB = cyVar.b();
        if (ec.a) {
            ec.a("decodeWakeUp success : %s", strB);
        }
        try {
            AppData appDataA = this.c.a(strB);
            if (this.a != null) {
                this.a.onWakeUpFinish(appDataA, null);
            }
            if (appDataA.isEmpty()) {
                return;
            }
            this.c.a(this.b);
        } catch (JSONException e) {
            if (ec.a) {
                ec.c("decodeWakeUp error : %s", e.toString());
            }
            AppWakeUpListener appWakeUpListener2 = this.a;
            if (appWakeUpListener2 != null) {
                appWakeUpListener2.onWakeUpFinish(null, Error.fromInner(cy.a.REQUEST_EXCEPTION));
            }
        }
    }
}
