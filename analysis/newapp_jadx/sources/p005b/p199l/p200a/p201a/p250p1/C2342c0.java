package p005b.p199l.p200a.p201a.p250p1;

import p403d.p404a.p405a.p407b.p408a.C4195m;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.a.a.p1.c0 */
/* loaded from: classes.dex */
public final class C2342c0 {

    /* renamed from: a */
    public long f6031a;

    /* renamed from: b */
    public long f6032b;

    /* renamed from: c */
    public volatile long f6033c = -9223372036854775807L;

    public C2342c0(long j2) {
        m2308d(j2);
    }

    /* renamed from: a */
    public long m2305a(long j2) {
        if (j2 == -9223372036854775807L) {
            return -9223372036854775807L;
        }
        if (this.f6033c != -9223372036854775807L) {
            this.f6033c = j2;
        } else {
            long j3 = this.f6031a;
            if (j3 != Long.MAX_VALUE) {
                this.f6032b = j3 - j2;
            }
            synchronized (this) {
                this.f6033c = j2;
                notifyAll();
            }
        }
        return j2 + this.f6032b;
    }

    /* renamed from: b */
    public long m2306b(long j2) {
        if (j2 == -9223372036854775807L) {
            return -9223372036854775807L;
        }
        if (this.f6033c != -9223372036854775807L) {
            long j3 = (this.f6033c * 90000) / 1000000;
            long j4 = (IjkMediaMeta.AV_CH_WIDE_RIGHT + j3) / IjkMediaMeta.AV_CH_SURROUND_DIRECT_LEFT;
            long j5 = ((j4 - 1) * IjkMediaMeta.AV_CH_SURROUND_DIRECT_LEFT) + j2;
            j2 += j4 * IjkMediaMeta.AV_CH_SURROUND_DIRECT_LEFT;
            if (Math.abs(j5 - j3) < Math.abs(j2 - j3)) {
                j2 = j5;
            }
        }
        return m2305a((j2 * 1000000) / 90000);
    }

    /* renamed from: c */
    public long m2307c() {
        if (this.f6031a == Long.MAX_VALUE) {
            return 0L;
        }
        if (this.f6033c == -9223372036854775807L) {
            return -9223372036854775807L;
        }
        return this.f6032b;
    }

    /* renamed from: d */
    public synchronized void m2308d(long j2) {
        C4195m.m4771I(this.f6033c == -9223372036854775807L);
        this.f6031a = j2;
    }
}
