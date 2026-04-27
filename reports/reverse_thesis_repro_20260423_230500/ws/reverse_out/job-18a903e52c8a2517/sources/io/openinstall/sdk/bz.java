package io.openinstall.sdk;

import android.os.SystemClock;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class bz implements Delayed {
    private final long a;
    private final boolean b;

    private bz(long j, boolean z) {
        this.a = SystemClock.elapsedRealtime() + j;
        this.b = z;
    }

    public static bz a() {
        return new bz(0L, false);
    }

    public static bz b() {
        return new bz(800L, true);
    }

    public int a(bz bzVar) {
        long j = this.a;
        long j2 = bzVar.a;
        if (j < j2) {
            return -1;
        }
        return j > j2 ? 1 : 0;
    }

    @Override // java.lang.Comparable
    /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
    public int compareTo(Delayed delayed) {
        return a((bz) delayed);
    }

    public boolean c() {
        return this.b;
    }

    @Override // java.util.concurrent.Delayed
    public long getDelay(TimeUnit timeUnit) {
        return timeUnit.convert(this.a - SystemClock.elapsedRealtime(), TimeUnit.MILLISECONDS);
    }
}
