package io.openinstall.sdk;

import android.util.Pair;
import java.util.concurrent.LinkedBlockingQueue;

/* JADX INFO: loaded from: classes3.dex */
class di implements Runnable {
    final /* synthetic */ LinkedBlockingQueue a;
    final /* synthetic */ dh b;

    di(dh dhVar, LinkedBlockingQueue linkedBlockingQueue) {
        this.b = dhVar;
        this.a = linkedBlockingQueue;
    }

    @Override // java.lang.Runnable
    public void run() {
        String str;
        LinkedBlockingQueue linkedBlockingQueue;
        String strA;
        by byVarB = this.b.h().b(true);
        if (byVarB == null || !byVarB.c(2)) {
            str = "aviw";
            if (byVarB == null || !byVarB.c(1)) {
                this.a.offer(Pair.create("aviw", (String) null));
                return;
            } else {
                linkedBlockingQueue = this.a;
                strA = byVarB.a();
            }
        } else {
            linkedBlockingQueue = this.a;
            strA = byVarB.b();
            str = "pwcf";
        }
        linkedBlockingQueue.offer(Pair.create(str, strA));
    }
}
