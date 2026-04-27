package io.openinstall.sdk;

import android.app.Activity;

/* JADX INFO: loaded from: classes3.dex */
class ba implements Runnable {
    final /* synthetic */ Activity a;

    ba(Activity activity) {
        this.a = activity;
    }

    @Override // java.lang.Runnable
    public void run() {
        az.a(this.a);
    }
}
