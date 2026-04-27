package io.openinstall.sdk;

import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
class bm implements Runnable {
    final /* synthetic */ bj a;

    bm(bj bjVar) {
        this.a = bjVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        int iMin = 100;
        int i = 0;
        while (true) {
            try {
                this.a.c.poll(iMin, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
            }
            if (!this.a.f && this.a.d() && i < 35 && i > 0) {
                as.a().b(true);
                this.a.e();
            }
            if (as.a().l()) {
                this.a.f = true;
                return;
            } else {
                this.a.d.a();
                iMin = Math.min(iMin * 10, 10000);
                i++;
            }
        }
    }
}
