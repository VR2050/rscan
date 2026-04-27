package io.openinstall.sdk;

import android.os.IBinder;

/* JADX INFO: loaded from: classes3.dex */
class y implements Runnable {
    final /* synthetic */ IBinder a;
    final /* synthetic */ x b;

    y(x xVar, IBinder iBinder) {
        this.b = xVar;
        this.a = iBinder;
    }

    @Override // java.lang.Runnable
    public void run() {
        try {
            this.b.c.put(this.a);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
