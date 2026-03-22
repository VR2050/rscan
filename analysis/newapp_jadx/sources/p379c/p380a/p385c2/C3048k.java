package p379c.p380a.p385c2;

import java.util.concurrent.TimeUnit;
import kotlin.jvm.JvmField;
import kotlin.ranges.RangesKt___RangesKt;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2971t;

/* renamed from: c.a.c2.k */
/* loaded from: classes2.dex */
public final class C3048k {

    /* renamed from: a */
    @JvmField
    public static final long f8382a = C2354n.m2427R1("kotlinx.coroutines.scheduler.resolution.ns", 100000, 0, 0, 12, null);

    /* renamed from: b */
    @JvmField
    public static final int f8383b;

    /* renamed from: c */
    @JvmField
    public static final int f8384c;

    /* renamed from: d */
    @JvmField
    public static final long f8385d;

    /* renamed from: e */
    @JvmField
    @NotNull
    public static AbstractC3049l f8386e;

    static {
        C2354n.m2424Q1("kotlinx.coroutines.scheduler.blocking.parallelism", 16, 0, 0, 12, null);
        int i2 = C2971t.f8136a;
        int m2424Q1 = C2354n.m2424Q1("kotlinx.coroutines.scheduler.core.pool.size", RangesKt___RangesKt.coerceAtLeast(i2, 2), 1, 0, 8, null);
        f8383b = m2424Q1;
        f8384c = C2354n.m2424Q1("kotlinx.coroutines.scheduler.max.pool.size", RangesKt___RangesKt.coerceIn(i2 * 128, m2424Q1, 2097150), 0, 2097150, 4, null);
        f8385d = TimeUnit.SECONDS.toNanos(C2354n.m2427R1("kotlinx.coroutines.scheduler.keep.alive.sec", 60L, 0L, 0L, 12, null));
        f8386e = C3043f.f8377a;
    }
}
