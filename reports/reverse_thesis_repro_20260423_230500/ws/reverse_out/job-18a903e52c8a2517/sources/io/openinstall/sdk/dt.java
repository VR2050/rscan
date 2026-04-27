package io.openinstall.sdk;

import java.util.concurrent.LinkedBlockingQueue;

/* JADX INFO: loaded from: classes3.dex */
class dt implements Runnable {
    final /* synthetic */ LinkedBlockingQueue a;
    final /* synthetic */ ds b;

    dt(ds dsVar, LinkedBlockingQueue linkedBlockingQueue) {
        this.b = dsVar;
        this.a = linkedBlockingQueue;
    }

    @Override // java.lang.Runnable
    public void run() {
        LinkedBlockingQueue linkedBlockingQueue;
        cv cvVar;
        by byVarA = this.b.a(this.b.h().b(true));
        this.b.h().a(false);
        if (this.b.h().a() && byVarA == null) {
            linkedBlockingQueue = this.a;
            cvVar = new cv("pbR", "jgkf", String.valueOf(false));
        } else if (byVarA != null && byVarA.c(2)) {
            this.a.offer(new cv("pbH", "pwcf", byVarA.b()));
            return;
        } else if (byVarA != null && byVarA.c(1)) {
            this.a.offer(new cv("pbT", "aviw", byVarA.a()));
            return;
        } else {
            linkedBlockingQueue = this.a;
            cvVar = new cv("pbT", "aviw", (String) null);
        }
        linkedBlockingQueue.offer(cvVar);
    }
}
