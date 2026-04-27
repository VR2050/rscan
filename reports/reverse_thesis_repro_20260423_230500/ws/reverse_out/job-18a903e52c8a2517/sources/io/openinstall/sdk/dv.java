package io.openinstall.sdk;

import java.util.concurrent.LinkedBlockingQueue;

/* JADX INFO: loaded from: classes3.dex */
class dv implements Runnable {
    final /* synthetic */ LinkedBlockingQueue a;
    final /* synthetic */ cw b;
    final /* synthetic */ ds c;

    dv(ds dsVar, LinkedBlockingQueue linkedBlockingQueue, cw cwVar) {
        this.c = dsVar;
        this.a = linkedBlockingQueue;
        this.b = cwVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        this.a.offer(this.b.a_());
    }
}
