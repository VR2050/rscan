package io.openinstall.sdk;

import android.app.Application;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.text.TextUtils;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

/* JADX INFO: loaded from: classes3.dex */
public class bj {
    private final bo d;
    private Application.ActivityLifecycleCallbacks e;
    private final Object a = new Object();
    private final LinkedBlockingQueue<Object> c = new LinkedBlockingQueue<>(1);
    private boolean f = false;
    private final Application b = (Application) as.a().c();

    public bj(av avVar) {
        HandlerThread handlerThread = new HandlerThread("EventsHandler");
        handlerThread.setUncaughtExceptionHandler(new bk(this));
        handlerThread.start();
        this.d = new bo(handlerThread.getLooper(), avVar);
    }

    private boolean a(String str) {
        return !TextUtils.isEmpty(str) && str.indexOf(44) < 0 && str.indexOf(59) < 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean d() {
        bd bdVarK = as.a().k();
        return (bdVarK == null || !bdVarK.a() || as.a().l() || as.a().d() == null || as.a().m()) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void e() {
        new Handler(Looper.getMainLooper()).postDelayed(new bn(this), 1000L);
    }

    public void a() {
        synchronized (this.a) {
            if (this.e != null) {
                return;
            }
            bl blVar = new bl(this);
            this.e = blVar;
            this.b.registerActivityLifecycleCallbacks(blVar);
        }
    }

    public void a(long j) {
        if (j >= 1) {
            be beVarA = be.a(j);
            beVarA.a(true);
            this.d.a(beVarA);
        }
    }

    public void a(String str, long j, Map<String, String> map) {
        if (!a(str)) {
            if (ec.a) {
                ec.b(dz.event_name_invalid.a(), str);
            }
        } else if (map == null || map.size() <= 10) {
            this.d.a(be.a(str, j, map));
        } else if (ec.a) {
            ec.c(dz.event_extra_larger.a(), new Object[0]);
        }
    }

    public void b() {
        Thread thread = new Thread(new bm(this));
        thread.setName("el");
        thread.start();
    }

    public void c() {
        be beVarA = be.a();
        beVarA.a(true);
        this.d.a(beVarA);
    }
}
