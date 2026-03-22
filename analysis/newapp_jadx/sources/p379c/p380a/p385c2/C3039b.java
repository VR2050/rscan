package p379c.p380a.p385c2;

import kotlin.ranges.RangesKt___RangesKt;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3036c0;
import p379c.p380a.p381a.C2971t;

/* renamed from: c.a.c2.b */
/* loaded from: classes2.dex */
public final class C3039b extends C3040c {

    /* renamed from: i */
    @NotNull
    public static final AbstractC3036c0 f8364i;

    /* renamed from: j */
    public static final C3039b f8365j;

    static {
        C3039b c3039b = new C3039b();
        f8365j = c3039b;
        f8364i = new ExecutorC3042e(c3039b, C2354n.m2424Q1("kotlinx.coroutines.io.parallelism", RangesKt___RangesKt.coerceAtLeast(64, C2971t.f8136a), 0, 0, 12, null), "Dispatchers.IO", 1);
    }

    public C3039b() {
        super(0, 0, null, 7);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        throw new UnsupportedOperationException("Dispatchers.Default cannot be closed");
    }

    @Override // p379c.p380a.AbstractC3036c0
    @NotNull
    public String toString() {
        return "Dispatchers.Default";
    }
}
