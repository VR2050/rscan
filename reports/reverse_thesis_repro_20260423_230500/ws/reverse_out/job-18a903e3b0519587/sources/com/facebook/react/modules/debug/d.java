package com.facebook.react.modules.debug;

import com.facebook.react.bridge.NotThreadSafeBridgeIdleDebugListener;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
public final class d implements NotThreadSafeBridgeIdleDebugListener, M1.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ArrayList f7061a = new ArrayList(20);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ArrayList f7062b = new ArrayList(20);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ArrayList f7063c = new ArrayList(20);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final ArrayList f7064d = new ArrayList(20);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private volatile boolean f7065e = true;

    private final boolean c(long j3, long j4) {
        long jE = e.e(this.f7061a, j3, j4);
        long jE2 = e.e(this.f7062b, j3, j4);
        return (jE == -1 && jE2 == -1) ? this.f7065e : jE > jE2;
    }

    @Override // M1.a
    public synchronized void a() {
        this.f7063c.add(Long.valueOf(System.nanoTime()));
    }

    @Override // M1.a
    public synchronized void b() {
        this.f7064d.add(Long.valueOf(System.nanoTime()));
    }

    public final synchronized boolean d(long j3, long j4) {
        boolean z3;
        try {
            boolean zF = e.f(this.f7064d, j3, j4);
            boolean zC = c(j3, j4);
            z3 = true;
            if (!zF && (!zC || e.f(this.f7063c, j3, j4))) {
                z3 = false;
            }
            e.d(this.f7061a, j4);
            e.d(this.f7062b, j4);
            e.d(this.f7063c, j4);
            e.d(this.f7064d, j4);
            this.f7065e = zC;
        } catch (Throwable th) {
            throw th;
        }
        return z3;
    }

    @Override // com.facebook.react.bridge.NotThreadSafeBridgeIdleDebugListener
    public synchronized void onBridgeDestroyed() {
    }

    @Override // com.facebook.react.bridge.NotThreadSafeBridgeIdleDebugListener
    public synchronized void onTransitionToBridgeBusy() {
        this.f7062b.add(Long.valueOf(System.nanoTime()));
    }

    @Override // com.facebook.react.bridge.NotThreadSafeBridgeIdleDebugListener
    public synchronized void onTransitionToBridgeIdle() {
        this.f7061a.add(Long.valueOf(System.nanoTime()));
    }
}
