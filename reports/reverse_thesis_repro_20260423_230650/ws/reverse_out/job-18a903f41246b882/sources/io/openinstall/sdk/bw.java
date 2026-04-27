package io.openinstall.sdk;

import android.app.Activity;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes3.dex */
class bw extends ap {
    final /* synthetic */ bv a;

    bw(bv bvVar) {
        this.a = bvVar;
    }

    @Override // io.openinstall.sdk.ap, android.app.Application.ActivityLifecycleCallbacks
    public void onActivityResumed(Activity activity) {
        activity.getWindow().getDecorView().postDelayed(this.a.h, 300L);
        this.a.e = new WeakReference(activity);
        bv bvVar = this.a;
        bvVar.a(bvVar.e);
    }
}
