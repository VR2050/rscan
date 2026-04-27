package io.openinstall.sdk;

import android.os.SystemClock;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
class bl extends bf {
    long a = SystemClock.uptimeMillis();
    final /* synthetic */ bj b;

    bl(bj bjVar) {
        this.b = bjVar;
    }

    @Override // io.openinstall.sdk.bf
    public void a() {
        this.a = SystemClock.uptimeMillis();
    }

    @Override // io.openinstall.sdk.bf
    public void b() {
        this.b.a(TimeUnit.MILLISECONDS.toSeconds(SystemClock.uptimeMillis() - this.a));
    }
}
