package p005b.p199l.p200a.p201a.p208f1.p210b0;

import androidx.annotation.Nullable;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p208f1.C2051r;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.b0.g */
/* loaded from: classes.dex */
public final class C1979g implements InterfaceC1977e {

    /* renamed from: a */
    public final long f3572a;

    /* renamed from: b */
    public final int f3573b;

    /* renamed from: c */
    public final long f3574c;

    /* renamed from: d */
    public final long f3575d;

    /* renamed from: e */
    public final long f3576e;

    /* renamed from: f */
    @Nullable
    public final long[] f3577f;

    public C1979g(long j2, int i2, long j3, long j4, @Nullable long[] jArr) {
        this.f3572a = j2;
        this.f3573b = i2;
        this.f3574c = j3;
        this.f3577f = jArr;
        this.f3575d = j4;
        this.f3576e = j4 != -1 ? j2 + j4 : -1L;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p210b0.InterfaceC1977e
    /* renamed from: a */
    public long mo1502a(long j2) {
        long j3 = j2 - this.f3572a;
        if (!mo1462c() || j3 <= this.f3573b) {
            return 0L;
        }
        long[] jArr = this.f3577f;
        Objects.requireNonNull(jArr);
        double d2 = (j3 * 256.0d) / this.f3575d;
        int m2326d = C2344d0.m2326d(jArr, (long) d2, true, true);
        long j4 = this.f3574c;
        long j5 = (m2326d * j4) / 100;
        long j6 = jArr[m2326d];
        int i2 = m2326d + 1;
        long j7 = (j4 * i2) / 100;
        return Math.round((j6 == (m2326d == 99 ? 256L : jArr[i2]) ? ShadowDrawableWrapper.COS_45 : (d2 - j6) / (r0 - j6)) * (j7 - j5)) + j5;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p210b0.InterfaceC1977e
    /* renamed from: b */
    public long mo1503b() {
        return this.f3576e;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: c */
    public boolean mo1462c() {
        return this.f3577f != null;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: g */
    public InterfaceC2050q.a mo1463g(long j2) {
        if (!mo1462c()) {
            return new InterfaceC2050q.a(new C2051r(0L, this.f3572a + this.f3573b));
        }
        long m2330h = C2344d0.m2330h(j2, 0L, this.f3574c);
        double d2 = (m2330h * 100.0d) / this.f3574c;
        double d3 = ShadowDrawableWrapper.COS_45;
        if (d2 > ShadowDrawableWrapper.COS_45) {
            if (d2 >= 100.0d) {
                d3 = 256.0d;
            } else {
                int i2 = (int) d2;
                long[] jArr = this.f3577f;
                Objects.requireNonNull(jArr);
                double d4 = jArr[i2];
                d3 = d4 + (((i2 == 99 ? 256.0d : jArr[i2 + 1]) - d4) * (d2 - i2));
            }
        }
        return new InterfaceC2050q.a(new C2051r(m2330h, this.f3572a + C2344d0.m2330h(Math.round((d3 / 256.0d) * this.f3575d), this.f3573b, this.f3575d - 1)));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: i */
    public long mo1464i() {
        return this.f3574c;
    }
}
