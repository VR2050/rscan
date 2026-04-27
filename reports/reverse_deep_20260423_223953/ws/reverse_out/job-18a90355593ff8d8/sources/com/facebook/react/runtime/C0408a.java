package com.facebook.react.runtime;

import java.util.Objects;

/* JADX INFO: renamed from: com.facebook.react.runtime.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0408a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    volatile Object f7272a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    Object f7273b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private volatile b f7274c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private volatile String f7275d;

    /* JADX INFO: renamed from: com.facebook.react.runtime.a$a, reason: collision with other inner class name */
    interface InterfaceC0112a {
        Object get();
    }

    /* JADX INFO: renamed from: com.facebook.react.runtime.a$b */
    enum b {
        Init,
        Creating,
        Success,
        Failure
    }

    public C0408a(Object obj) {
        this.f7272a = obj;
        this.f7273b = obj;
        this.f7274c = b.Init;
        this.f7275d = "";
    }

    public synchronized Object a() {
        return Z0.a.c(this.f7272a);
    }

    public synchronized Object b() {
        Object objA;
        objA = a();
        e();
        return objA;
    }

    public synchronized Object c() {
        return this.f7272a;
    }

    public Object d(InterfaceC0112a interfaceC0112a) {
        boolean z3;
        Object objA;
        Object objA2;
        synchronized (this) {
            try {
                b bVar = this.f7274c;
                b bVar2 = b.Success;
                if (bVar == bVar2) {
                    return a();
                }
                if (this.f7274c == b.Failure) {
                    throw new RuntimeException("BridgelessAtomicRef: Failed to create object. Reason: " + this.f7275d);
                }
                b bVar3 = this.f7274c;
                b bVar4 = b.Creating;
                boolean z4 = false;
                if (bVar3 != bVar4) {
                    this.f7274c = bVar4;
                    z3 = true;
                } else {
                    z3 = false;
                }
                if (z3) {
                    try {
                        this.f7272a = interfaceC0112a.get();
                        synchronized (this) {
                            this.f7274c = bVar2;
                            notifyAll();
                            objA = a();
                        }
                        return objA;
                    } catch (RuntimeException e3) {
                        synchronized (this) {
                            this.f7274c = b.Failure;
                            this.f7275d = Objects.toString(e3.getMessage(), "null");
                            notifyAll();
                            throw new RuntimeException("BridgelessAtomicRef: Failed to create object.", e3);
                        }
                    }
                }
                synchronized (this) {
                    while (this.f7274c == b.Creating) {
                        try {
                            wait();
                        } catch (InterruptedException unused) {
                            z4 = true;
                        }
                    }
                    if (z4) {
                        Thread.currentThread().interrupt();
                    }
                    if (this.f7274c == b.Failure) {
                        throw new RuntimeException("BridgelessAtomicRef: Failed to create object. Reason: " + this.f7275d);
                    }
                    objA2 = a();
                }
                return objA2;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public synchronized void e() {
        this.f7272a = this.f7273b;
        this.f7274c = b.Init;
        this.f7275d = "";
    }

    public C0408a() {
        this(null);
    }
}
