package p474l;

import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.v */
/* loaded from: classes3.dex */
public final class C4760v {

    /* renamed from: b */
    public static final int f12175b;

    /* renamed from: c */
    public static final AtomicReference<C4759u>[] f12176c;

    /* renamed from: d */
    public static final C4760v f12177d = new C4760v();

    /* renamed from: a */
    public static final C4759u f12174a = new C4759u(new byte[0], 0, 0, false, false);

    static {
        int highestOneBit = Integer.highestOneBit((Runtime.getRuntime().availableProcessors() * 2) - 1);
        f12175b = highestOneBit;
        AtomicReference<C4759u>[] atomicReferenceArr = new AtomicReference[highestOneBit];
        for (int i2 = 0; i2 < highestOneBit; i2++) {
            atomicReferenceArr[i2] = new AtomicReference<>();
        }
        f12176c = atomicReferenceArr;
    }

    @JvmStatic
    /* renamed from: a */
    public static final void m5424a(@NotNull C4759u segment) {
        Intrinsics.checkNotNullParameter(segment, "segment");
        if (!(segment.f12172f == null && segment.f12173g == null)) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        if (segment.f12170d) {
            return;
        }
        Thread currentThread = Thread.currentThread();
        Intrinsics.checkNotNullExpressionValue(currentThread, "Thread.currentThread()");
        AtomicReference<C4759u> atomicReference = f12176c[(int) (currentThread.getId() & (f12175b - 1))];
        C4759u c4759u = atomicReference.get();
        if (c4759u == f12174a) {
            return;
        }
        int i2 = c4759u != null ? c4759u.f12169c : 0;
        if (i2 >= 65536) {
            return;
        }
        segment.f12172f = c4759u;
        segment.f12168b = 0;
        segment.f12169c = i2 + 8192;
        if (atomicReference.compareAndSet(c4759u, segment)) {
            return;
        }
        segment.f12172f = null;
    }

    @JvmStatic
    @NotNull
    /* renamed from: b */
    public static final C4759u m5425b() {
        Thread currentThread = Thread.currentThread();
        Intrinsics.checkNotNullExpressionValue(currentThread, "Thread.currentThread()");
        AtomicReference<C4759u> atomicReference = f12176c[(int) (currentThread.getId() & (f12175b - 1))];
        C4759u c4759u = f12174a;
        C4759u andSet = atomicReference.getAndSet(c4759u);
        if (andSet == c4759u) {
            return new C4759u();
        }
        if (andSet == null) {
            atomicReference.set(null);
            return new C4759u();
        }
        atomicReference.set(andSet.f12172f);
        andSet.f12172f = null;
        andSet.f12169c = 0;
        return andSet;
    }
}
