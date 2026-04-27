package com.facebook.common.time;

import e0.InterfaceC0513c;

/* JADX INFO: loaded from: classes.dex */
public class AwakeTimeSinceBootClock implements InterfaceC0513c {
    private static final AwakeTimeSinceBootClock INSTANCE = new AwakeTimeSinceBootClock();

    private AwakeTimeSinceBootClock() {
    }

    public static AwakeTimeSinceBootClock get() {
        return INSTANCE;
    }

    @Override // e0.InterfaceC0513c, e0.InterfaceC0512b
    public /* bridge */ /* synthetic */ long now() {
        return super.now();
    }

    @Override // e0.InterfaceC0513c, e0.InterfaceC0512b
    public long nowNanos() {
        return System.nanoTime();
    }
}
