package com.facebook.common.time;

import android.os.SystemClock;
import e0.InterfaceC0512b;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public class RealtimeSinceBootClock implements InterfaceC0512b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final RealtimeSinceBootClock f5834a = new RealtimeSinceBootClock();

    private RealtimeSinceBootClock() {
    }

    public static RealtimeSinceBootClock get() {
        return f5834a;
    }

    @Override // e0.InterfaceC0512b
    public long now() {
        return SystemClock.elapsedRealtime();
    }

    @Override // e0.InterfaceC0512b
    public long nowNanos() {
        return TimeUnit.MILLISECONDS.toNanos(now());
    }
}
