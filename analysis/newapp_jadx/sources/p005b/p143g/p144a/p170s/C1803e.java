package p005b.p143g.p144a.p170s;

import android.os.SystemClock;

/* renamed from: b.g.a.s.e */
/* loaded from: classes.dex */
public final class C1803e {

    /* renamed from: a */
    public static final double f2758a = 1.0d / Math.pow(10.0d, 6.0d);

    /* renamed from: b */
    public static final /* synthetic */ int f2759b = 0;

    /* renamed from: a */
    public static double m1138a(long j2) {
        return (SystemClock.elapsedRealtimeNanos() - j2) * f2758a;
    }
}
