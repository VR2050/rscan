package io.openinstall.sdk;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;

/* JADX INFO: loaded from: classes3.dex */
public abstract class bf extends ap {
    private Runnable a = null;
    private final Handler b = new Handler(Looper.getMainLooper());
    private volatile boolean c = true;
    private volatile boolean d = false;

    protected bf() {
    }

    public abstract void a();

    public abstract void b();

    @Override // io.openinstall.sdk.ap, android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPaused(Activity activity) {
        super.onActivityPaused(activity);
        this.d = true;
        as.a().a((Activity) null);
        Runnable runnable = this.a;
        if (runnable != null) {
            this.b.removeCallbacks(runnable);
        }
        bg bgVar = new bg(this);
        this.a = bgVar;
        this.b.postDelayed(bgVar, 500L);
    }

    @Override // io.openinstall.sdk.ap, android.app.Application.ActivityLifecycleCallbacks
    public void onActivityResumed(Activity activity) {
        super.onActivityResumed(activity);
        bd bdVarK = as.a().k();
        if (as.a().n() || (bdVarK != null && bdVarK.a())) {
            as.a().a(activity);
        }
        boolean z = !this.c;
        this.c = true;
        this.d = false;
        Runnable runnable = this.a;
        if (runnable != null) {
            this.b.removeCallbacks(runnable);
            this.a = null;
        }
        if (z) {
            a();
        }
    }
}
