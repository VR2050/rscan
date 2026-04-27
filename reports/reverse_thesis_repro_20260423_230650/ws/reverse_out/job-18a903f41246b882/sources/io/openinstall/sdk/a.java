package io.openinstall.sdk;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import com.fm.openinstall.Configuration;
import com.fm.openinstall.listener.AppInstallListener;
import com.fm.openinstall.listener.AppWakeUpListener;
import com.fm.openinstall.listener.ResultCallback;
import com.fm.openinstall.model.Error;
import io.openinstall.sdk.cy;
import java.io.File;
import java.lang.ref.WeakReference;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public final class a {
    private final av a;
    private bj b;

    /* JADX INFO: renamed from: io.openinstall.sdk.a$a, reason: collision with other inner class name */
    private static class C0059a {
        public static a a = new a(null);
    }

    private a() {
        this.a = new i();
    }

    /* synthetic */ a(b bVar) {
        this();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0032 A[PHI: r4
      0x0032: PHI (r4v5 java.lang.String) = (r4v3 java.lang.String), (r4v4 java.lang.String) binds: [B:12:0x0030, B:15:0x0040] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019 A[PHI: r4
      0x0019: PHI (r4v7 java.lang.String) = (r4v1 java.lang.String), (r4v2 java.lang.String) binds: [B:6:0x0017, B:9:0x0027] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.fm.openinstall.model.AppData a(java.lang.String r4) throws org.json.JSONException {
        /*
            r3 = this;
            com.fm.openinstall.model.AppData r0 = new com.fm.openinstall.model.AppData
            r0.<init>()
            boolean r1 = android.text.TextUtils.isEmpty(r4)
            if (r1 == 0) goto Lc
            return r0
        Lc:
            org.json.JSONObject r1 = new org.json.JSONObject
            r1.<init>(r4)
            java.lang.String r4 = "channelCode"
            boolean r2 = r1.has(r4)
            if (r2 == 0) goto L21
        L19:
            java.lang.String r4 = r1.optString(r4)
            r0.setChannel(r4)
            goto L2a
        L21:
            java.lang.String r4 = "c"
            boolean r2 = r1.has(r4)
            if (r2 == 0) goto L2a
            goto L19
        L2a:
            java.lang.String r4 = "bind"
            boolean r2 = r1.has(r4)
            if (r2 == 0) goto L3a
        L32:
            java.lang.String r4 = r1.optString(r4)
            r0.setData(r4)
            goto L43
        L3a:
            java.lang.String r4 = "d"
            boolean r2 = r1.has(r4)
            if (r2 == 0) goto L43
            goto L32
        L43:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: io.openinstall.sdk.a.a(java.lang.String):com.fm.openinstall.model.AppData");
    }

    public static a a() {
        return C0059a.a;
    }

    private void a(Uri uri, AppWakeUpListener appWakeUpListener) {
        if (ec.a) {
            ec.a("decodeWakeUp", new Object[0]);
        }
        System.currentTimeMillis();
        new dh(this.a, uri, new b(this, appWakeUpListener, uri)).l();
        System.currentTimeMillis();
    }

    public void a(Intent intent, AppWakeUpListener appWakeUpListener) {
        a(intent.getData(), appWakeUpListener);
    }

    public void a(Uri uri) {
        new dl(this.a, uri).l();
    }

    public void a(Configuration configuration, WeakReference<Activity> weakReference, long j) {
        if (configuration == null) {
            configuration = Configuration.getDefault();
        }
        this.a.c().a(new h(this.a.g(), configuration));
        this.a.c().a(new f());
        ds dsVar = new ds(this.a, weakReference);
        dsVar.a(new g(as.a().c(), configuration));
        dsVar.l();
        new dq(this.a).l();
        this.b.b();
        System.currentTimeMillis();
    }

    public void a(AppWakeUpListener appWakeUpListener) {
        a((Uri) null, appWakeUpListener);
    }

    public void a(ResultCallback<File> resultCallback) {
        if (ec.a) {
            ec.a("getOriginalApk", new Object[0]);
        }
        System.currentTimeMillis();
        new dr(this.a, new e(this, resultCallback)).l();
        System.currentTimeMillis();
    }

    public void a(String str, long j) {
        a(str, j, (Map<String, String>) null);
    }

    public void a(String str, long j, Map<String, String> map) {
        if (ec.a) {
            ec.a("reportEffectPoint", new Object[0]);
        }
        this.b.a(str, j, map);
    }

    public void a(String str, String str2, ResultCallback<Void> resultCallback) {
        if (ec.a) {
            ec.a("reportShare", new Object[0]);
        }
        if (TextUtils.isEmpty(str)) {
            if (ec.a) {
                ec.c("shareCode 为空", new Object[0]);
            }
            resultCallback.onResult(null, Error.fromInner(cy.a.REQUEST_ERROR.a("shareCode 不能为空").c()));
            return;
        }
        if (str.length() > 128 && ec.a) {
            ec.b("shareCode 长度超过128位", new Object[0]);
        }
        System.currentTimeMillis();
        bh bhVar = new bh(str);
        bhVar.a(str2);
        new dk(this.a, bhVar, new d(this, resultCallback)).l();
        System.currentTimeMillis();
    }

    public void a(boolean z, int i, AppInstallListener appInstallListener) {
        if (ec.a) {
            ec.a("getInstallData", new Object[0]);
        }
        System.currentTimeMillis();
        dg dgVar = new dg(this.a, z, new c(this, appInstallListener));
        dgVar.a(i);
        dgVar.l();
        System.currentTimeMillis();
    }

    public String b() {
        return this.a.f().h();
    }

    public void c() {
        bj bjVar = new bj(this.a);
        this.b = bjVar;
        bjVar.a();
        new Cdo(this.a, new j()).l();
    }

    public void d() {
        if (ec.a) {
            ec.a("reportRegister", new Object[0]);
        }
        this.b.c();
    }
}
