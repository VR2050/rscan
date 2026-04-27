package io.openinstall.sdk;

import java.util.concurrent.LinkedBlockingQueue;

/* JADX INFO: loaded from: classes3.dex */
class du implements Runnable {
    final /* synthetic */ LinkedBlockingQueue a;
    final /* synthetic */ ds b;

    du(ds dsVar, LinkedBlockingQueue linkedBlockingQueue) {
        this.b = dsVar;
        this.a = linkedBlockingQueue;
    }

    @Override // java.lang.Runnable
    public void run() {
        this.a.offer(new cv("aI", "ihse", this.b.f().l()));
    }
}
