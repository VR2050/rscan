package p005b.p199l.p200a.p201a.p245m1;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroup;
import java.util.List;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l;
import p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2131m;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f;

/* renamed from: b.l.a.a.m1.a */
/* loaded from: classes.dex */
public class C2252a extends AbstractC2253b {

    /* renamed from: g */
    public final b f5623g;

    /* renamed from: h */
    public final long f5624h;

    /* renamed from: i */
    public final long f5625i;

    /* renamed from: j */
    public final long f5626j;

    /* renamed from: k */
    public final float f5627k;

    /* renamed from: l */
    public final long f5628l;

    /* renamed from: m */
    public final InterfaceC2346f f5629m;

    /* renamed from: n */
    public float f5630n;

    /* renamed from: o */
    public int f5631o;

    /* renamed from: p */
    public int f5632p;

    /* renamed from: q */
    public long f5633q;

    /* renamed from: b.l.a.a.m1.a$b */
    public interface b {
    }

    /* renamed from: b.l.a.a.m1.a$c */
    public static final class c implements b {

        /* renamed from: a */
        public final InterfaceC2292g f5634a;

        /* renamed from: b */
        public final float f5635b;

        /* renamed from: c */
        public final long f5636c;

        /* renamed from: d */
        @Nullable
        public long[][] f5637d;

        public c(InterfaceC2292g interfaceC2292g, float f2, long j2) {
            this.f5634a = interfaceC2292g;
            this.f5635b = f2;
            this.f5636c = j2;
        }
    }

    /* renamed from: b.l.a.a.m1.a$d */
    public static class d implements InterfaceC2257f.b {

        /* renamed from: a */
        public final InterfaceC2346f f5638a = InterfaceC2346f.f6053a;
    }

    public C2252a(TrackGroup trackGroup, int[] iArr, b bVar, long j2, long j3, long j4, float f2, long j5, InterfaceC2346f interfaceC2346f, a aVar) {
        super(trackGroup, iArr);
        this.f5623g = bVar;
        this.f5624h = j2 * 1000;
        this.f5625i = j3 * 1000;
        this.f5626j = j4 * 1000;
        this.f5627k = f2;
        this.f5628l = j5;
        this.f5629m = interfaceC2346f;
        this.f5630n = 1.0f;
        this.f5632p = 0;
        this.f5633q = -9223372036854775807L;
    }

    /* renamed from: t */
    public static void m2144t(long[][][] jArr, int i2, long[][] jArr2, int[] iArr) {
        long j2 = 0;
        for (int i3 = 0; i3 < jArr.length; i3++) {
            jArr[i3][i2][1] = jArr2[i3][iArr[i3]];
            j2 += jArr[i3][i2][1];
        }
        for (long[][] jArr3 : jArr) {
            jArr3[i2][0] = j2;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: b */
    public int mo1941b() {
        return this.f5631o;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.AbstractC2253b, p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: f */
    public void mo2145f() {
        this.f5633q = -9223372036854775807L;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.AbstractC2253b, p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: h */
    public int mo2146h(long j2, List<? extends AbstractC2130l> list) {
        int i2;
        int i3;
        long mo2354c = this.f5629m.mo2354c();
        long j3 = this.f5633q;
        if (!(j3 == -9223372036854775807L || mo2354c - j3 >= this.f5628l)) {
            return list.size();
        }
        this.f5633q = mo2354c;
        if (list.isEmpty()) {
            return 0;
        }
        int size = list.size();
        long m2338p = C2344d0.m2338p(list.get(size - 1).f4628f - j2, this.f5630n);
        long j4 = this.f5626j;
        if (m2338p < j4) {
            return size;
        }
        Format format = this.f5642d[m2148s(mo2354c)];
        for (int i4 = 0; i4 < size; i4++) {
            AbstractC2130l abstractC2130l = list.get(i4);
            Format format2 = abstractC2130l.f4625c;
            if (C2344d0.m2338p(abstractC2130l.f4628f - j2, this.f5630n) >= j4 && format2.f9241h < format.f9241h && (i2 = format2.f9251r) != -1 && i2 < 720 && (i3 = format2.f9250q) != -1 && i3 < 1280 && i2 < format.f9251r) {
                return i4;
            }
        }
        return size;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: j */
    public void mo1942j(long j2, long j3, long j4, List<? extends AbstractC2130l> list, InterfaceC2131m[] interfaceC2131mArr) {
        long mo2354c = this.f5629m.mo2354c();
        if (this.f5632p == 0) {
            this.f5632p = 1;
            this.f5631o = m2148s(mo2354c);
            return;
        }
        int i2 = this.f5631o;
        int m2148s = m2148s(mo2354c);
        this.f5631o = m2148s;
        if (m2148s == i2) {
            return;
        }
        if (!m2159r(i2, mo2354c)) {
            Format[] formatArr = this.f5642d;
            Format format = formatArr[i2];
            int i3 = formatArr[this.f5631o].f9241h;
            int i4 = format.f9241h;
            if (i3 > i4) {
                if (j3 < (j4 != -9223372036854775807L && j4 <= this.f5624h ? (long) (j4 * this.f5627k) : this.f5624h)) {
                    this.f5631o = i2;
                }
            }
            if (i3 < i4 && j3 >= this.f5625i) {
                this.f5631o = i2;
            }
        }
        if (this.f5631o != i2) {
            this.f5632p = 3;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: m */
    public int mo1943m() {
        return this.f5632p;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.AbstractC2253b, p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    /* renamed from: n */
    public void mo2147n(float f2) {
        this.f5630n = f2;
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
    @Nullable
    /* renamed from: o */
    public Object mo1944o() {
        return null;
    }

    /* renamed from: s */
    public final int m2148s(long j2) {
        long[][] jArr;
        c cVar = (c) this.f5623g;
        long max = Math.max(0L, ((long) (cVar.f5634a.mo2198e() * cVar.f5635b)) - cVar.f5636c);
        if (cVar.f5637d != null) {
            int i2 = 1;
            while (true) {
                jArr = cVar.f5637d;
                if (i2 >= jArr.length - 1 || jArr[i2][0] >= max) {
                    break;
                }
                i2++;
            }
            long[] jArr2 = jArr[i2 - 1];
            long[] jArr3 = jArr[i2];
            max = jArr2[1] + ((long) (((max - jArr2[0]) / (jArr3[0] - jArr2[0])) * (jArr3[1] - jArr2[1])));
        }
        int i3 = 0;
        for (int i4 = 0; i4 < this.f5640b; i4++) {
            if (j2 == Long.MIN_VALUE || !m2159r(i4, j2)) {
                if (((long) Math.round(((float) this.f5642d[i4].f9241h) * this.f5630n)) <= max) {
                    return i4;
                }
                i3 = i4;
            }
        }
        return i3;
    }
}
