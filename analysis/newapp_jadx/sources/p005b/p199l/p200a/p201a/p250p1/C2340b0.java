package p005b.p199l.p200a.p201a.p250p1;

import androidx.annotation.Nullable;
import java.util.Arrays;

/* renamed from: b.l.a.a.p1.b0 */
/* loaded from: classes.dex */
public final class C2340b0<V> {

    /* renamed from: a */
    public long[] f6026a = new long[10];

    /* renamed from: b */
    public V[] f6027b = (V[]) new Object[10];

    /* renamed from: c */
    public int f6028c;

    /* renamed from: d */
    public int f6029d;

    /* renamed from: a */
    public synchronized void m2300a(long j2, V v) {
        if (this.f6029d > 0) {
            if (j2 <= this.f6026a[((this.f6028c + r0) - 1) % this.f6027b.length]) {
                m2301b();
            }
        }
        m2302c();
        int i2 = this.f6028c;
        int i3 = this.f6029d;
        V[] vArr = this.f6027b;
        int length = (i2 + i3) % vArr.length;
        this.f6026a[length] = j2;
        vArr[length] = v;
        this.f6029d = i3 + 1;
    }

    /* renamed from: b */
    public synchronized void m2301b() {
        this.f6028c = 0;
        this.f6029d = 0;
        Arrays.fill(this.f6027b, (Object) null);
    }

    /* renamed from: c */
    public final void m2302c() {
        int length = this.f6027b.length;
        if (this.f6029d < length) {
            return;
        }
        int i2 = length * 2;
        long[] jArr = new long[i2];
        V[] vArr = (V[]) new Object[i2];
        int i3 = this.f6028c;
        int i4 = length - i3;
        System.arraycopy(this.f6026a, i3, jArr, 0, i4);
        System.arraycopy(this.f6027b, this.f6028c, vArr, 0, i4);
        int i5 = this.f6028c;
        if (i5 > 0) {
            System.arraycopy(this.f6026a, 0, jArr, i4, i5);
            System.arraycopy(this.f6027b, 0, vArr, i4, this.f6028c);
        }
        this.f6026a = jArr;
        this.f6027b = vArr;
        this.f6028c = 0;
    }

    @Nullable
    /* renamed from: d */
    public final V m2303d(long j2, boolean z) {
        long j3 = Long.MAX_VALUE;
        V v = null;
        while (true) {
            int i2 = this.f6029d;
            if (i2 <= 0) {
                break;
            }
            long[] jArr = this.f6026a;
            int i3 = this.f6028c;
            long j4 = j2 - jArr[i3];
            if (j4 < 0 && (z || (-j4) >= j3)) {
                break;
            }
            V[] vArr = this.f6027b;
            v = vArr[i3];
            vArr[i3] = null;
            this.f6028c = (i3 + 1) % vArr.length;
            this.f6029d = i2 - 1;
            j3 = j4;
        }
        return v;
    }

    @Nullable
    /* renamed from: e */
    public synchronized V m2304e(long j2) {
        return m2303d(j2, true);
    }
}
