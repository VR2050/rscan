package com.qunidayede.service;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import androidx.annotation.Nullable;
import java.io.File;
import java.util.concurrent.TimeUnit;
import p005b.p113c0.p114a.C1409a;
import p005b.p113c0.p114a.InterfaceC1414f;
import p005b.p113c0.p114a.p129k.AbstractC1487c;
import p005b.p113c0.p114a.p129k.C1488d;
import p005b.p113c0.p114a.p129k.RunnableC1485a;
import p005b.p113c0.p114a.p129k.RunnableC1486b;
import p005b.p113c0.p114a.p130l.C1490b;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p327w.p328a.C2821a;

/* loaded from: classes2.dex */
public class CoreService extends Service {

    /* renamed from: c */
    public InterfaceC1414f f10257c;

    /* renamed from: com.qunidayede.service.CoreService$a */
    public class C4029a implements InterfaceC1414f.a {
        public C4029a() {
        }
    }

    @Override // android.app.Service
    @Nullable
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override // android.app.Service
    public void onCreate() {
        File externalFilesDir = getExternalFilesDir(null);
        if (externalFilesDir == null) {
            externalFilesDir = getCacheDir();
        }
        StringBuilder sb = new StringBuilder();
        sb.append(externalFilesDir.getPath());
        String m582D = C1499a.m582D(sb, File.separator, "movies");
        File file = new File(m582D);
        if (!file.exists()) {
            file.mkdirs();
        }
        C2821a.f7664a = m582D;
        String str = C1409a.f1362a;
        C1488d.b bVar = new C1488d.b(this, "default", null);
        bVar.f1488a = 54312;
        bVar.f1489b = (int) Math.min(TimeUnit.SECONDS.toMillis(10), 2147483647L);
        bVar.f1490c = new C4029a();
        this.f10257c = new C1488d(bVar, null);
    }

    @Override // android.app.Service
    public void onDestroy() {
        AbstractC1487c abstractC1487c = (AbstractC1487c) this.f10257c;
        if (abstractC1487c.f1487e) {
            C1490b m560a = C1490b.m560a();
            m560a.f1498c.execute(new RunnableC1486b(abstractC1487c));
        }
        super.onDestroy();
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int i2, int i3) {
        AbstractC1487c abstractC1487c = (AbstractC1487c) this.f10257c;
        if (abstractC1487c.f1487e) {
            return 1;
        }
        C1490b m560a = C1490b.m560a();
        m560a.f1498c.execute(new RunnableC1485a(abstractC1487c));
        return 1;
    }
}
