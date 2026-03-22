package p458k;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ExecutorService;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p458k.C4379f0;

/* renamed from: k.s */
/* loaded from: classes3.dex */
public final class C4482s {

    /* renamed from: a */
    public ExecutorService f12020a;

    /* renamed from: b */
    public final ArrayDeque<C4379f0.a> f12021b = new ArrayDeque<>();

    /* renamed from: c */
    public final ArrayDeque<C4379f0.a> f12022c = new ArrayDeque<>();

    /* renamed from: d */
    public final ArrayDeque<C4379f0> f12023d = new ArrayDeque<>();

    /* renamed from: a */
    public final <T> void m5265a(Deque<T> deque, T t) {
        synchronized (this) {
            if (!deque.remove(t)) {
                throw new AssertionError("Call wasn't in-flight!");
            }
            Unit unit = Unit.INSTANCE;
        }
        m5267c();
    }

    /* renamed from: b */
    public final void m5266b(@NotNull C4379f0.a call) {
        Intrinsics.checkParameterIsNotNull(call, "call");
        call.f11436c.decrementAndGet();
        m5265a(this.f12022c, call);
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0069  */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m5267c() {
        /*
            Method dump skipped, instructions count: 245
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.C4482s.m5267c():boolean");
    }
}
