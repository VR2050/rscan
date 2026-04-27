package Q2;

import java.util.concurrent.atomic.AtomicReference;

/* JADX INFO: loaded from: classes.dex */
public final class B {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final int f2516c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final AtomicReference[] f2517d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final B f2518e = new B();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final int f2514a = 65536;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final A f2515b = new A(new byte[0], 0, 0, false, false);

    static {
        int iHighestOneBit = Integer.highestOneBit((Runtime.getRuntime().availableProcessors() * 2) - 1);
        f2516c = iHighestOneBit;
        AtomicReference[] atomicReferenceArr = new AtomicReference[iHighestOneBit];
        for (int i3 = 0; i3 < iHighestOneBit; i3++) {
            atomicReferenceArr[i3] = new AtomicReference();
        }
        f2517d = atomicReferenceArr;
    }

    private B() {
    }

    private final AtomicReference a() {
        Thread threadCurrentThread = Thread.currentThread();
        t2.j.e(threadCurrentThread, "Thread.currentThread()");
        return f2517d[(int) (threadCurrentThread.getId() & (((long) f2516c) - 1))];
    }

    public static final void b(A a3) {
        t2.j.f(a3, "segment");
        if (!(a3.f2512f == null && a3.f2513g == null)) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        if (a3.f2510d) {
            return;
        }
        AtomicReference atomicReferenceA = f2518e.a();
        A a4 = (A) atomicReferenceA.get();
        if (a4 == f2515b) {
            return;
        }
        int i3 = a4 != null ? a4.f2509c : 0;
        if (i3 >= f2514a) {
            return;
        }
        a3.f2512f = a4;
        a3.f2508b = 0;
        a3.f2509c = i3 + 8192;
        if (com.facebook.jni.a.a(atomicReferenceA, a4, a3)) {
            return;
        }
        a3.f2512f = null;
    }

    public static final A c() {
        AtomicReference atomicReferenceA = f2518e.a();
        A a3 = f2515b;
        A a4 = (A) atomicReferenceA.getAndSet(a3);
        if (a4 == a3) {
            return new A();
        }
        if (a4 == null) {
            atomicReferenceA.set(null);
            return new A();
        }
        atomicReferenceA.set(a4.f2512f);
        a4.f2512f = null;
        a4.f2509c = 0;
        return a4;
    }
}
