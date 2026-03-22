package p005b.p199l.p200a.p201a.p245m1;

import android.os.SystemClock;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroup;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.m1.b */
/* loaded from: classes.dex */
public abstract class AbstractC2253b implements InterfaceC2257f {

    /* renamed from: a */
    public final TrackGroup f5639a;

    /* renamed from: b */
    public final int f5640b;

    /* renamed from: c */
    public final int[] f5641c;

    /* renamed from: d */
    public final Format[] f5642d;

    /* renamed from: e */
    public final long[] f5643e;

    /* renamed from: f */
    public int f5644f;

    /* renamed from: b.l.a.a.m1.b$b */
    public static final class b implements Comparator<Format> {
        public b(a aVar) {
        }

        @Override // java.util.Comparator
        public int compare(Format format, Format format2) {
            return format2.f9241h - format.f9241h;
        }
    }

    public AbstractC2253b(TrackGroup trackGroup, int... iArr) {
        int i2 = 0;
        C4195m.m4771I(iArr.length > 0);
        Objects.requireNonNull(trackGroup);
        this.f5639a = trackGroup;
        int length = iArr.length;
        this.f5640b = length;
        this.f5642d = new Format[length];
        for (int i3 = 0; i3 < iArr.length; i3++) {
            this.f5642d[i3] = trackGroup.f9394e[iArr[i3]];
        }
        Arrays.sort(this.f5642d, new b(null));
        this.f5641c = new int[this.f5640b];
        while (true) {
            int i4 = this.f5640b;
            if (i2 >= i4) {
                this.f5643e = new long[i4];
                return;
            } else {
                this.f5641c[i2] = trackGroup.m4059b(this.f5642d[i2]);
                i2++;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: a */
    public final TrackGroup mo2149a() {
        return this.f5639a;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: c */
    public final boolean mo2150c(int i2, long j2) {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        boolean m2159r = m2159r(i2, elapsedRealtime);
        int i3 = 0;
        while (i3 < this.f5640b && !m2159r) {
            m2159r = (i3 == i2 || m2159r(i3, elapsedRealtime)) ? false : true;
            i3++;
        }
        if (!m2159r) {
            return false;
        }
        long[] jArr = this.f5643e;
        long j3 = jArr[i2];
        int i4 = C2344d0.f6035a;
        long j4 = elapsedRealtime + j2;
        jArr[i2] = Math.max(j3, ((j2 ^ j4) & (elapsedRealtime ^ j4)) >= 0 ? j4 : Long.MAX_VALUE);
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: d */
    public void mo2151d() {
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: e */
    public final Format mo2152e(int i2) {
        return this.f5642d[i2];
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        AbstractC2253b abstractC2253b = (AbstractC2253b) obj;
        return this.f5639a == abstractC2253b.f5639a && Arrays.equals(this.f5641c, abstractC2253b.f5641c);
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: f */
    public void mo2145f() {
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: g */
    public final int mo2153g(int i2) {
        return this.f5641c[i2];
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: h */
    public int mo2146h(long j2, List<? extends AbstractC2130l> list) {
        return list.size();
    }

    public int hashCode() {
        if (this.f5644f == 0) {
            this.f5644f = Arrays.hashCode(this.f5641c) + (System.identityHashCode(this.f5639a) * 31);
        }
        return this.f5644f;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: i */
    public final int mo2154i(Format format) {
        for (int i2 = 0; i2 < this.f5640b; i2++) {
            if (this.f5642d[i2] == format) {
                return i2;
            }
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: k */
    public final int mo2155k() {
        return this.f5641c[mo1941b()];
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: l */
    public final Format mo2156l() {
        return this.f5642d[mo1941b()];
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    public final int length() {
        return this.f5641c.length;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: n */
    public void mo2147n(float f2) {
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: p */
    public /* synthetic */ void mo2157p() {
        C2256e.m2163a(this);
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: q */
    public final int mo2158q(int i2) {
        for (int i3 = 0; i3 < this.f5640b; i3++) {
            if (this.f5641c[i3] == i2) {
                return i3;
            }
        }
        return -1;
    }

    /* renamed from: r */
    public final boolean m2159r(int i2, long j2) {
        return this.f5643e[i2] > j2;
    }
}
