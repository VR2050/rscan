package p005b.p199l.p200a.p201a.p227k1.p228j0;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.j0.a */
/* loaded from: classes.dex */
public final class C2117a {

    /* renamed from: a */
    public static final C2117a f4606a = new C2117a(new long[0]);

    /* renamed from: b */
    public final int f4607b;

    /* renamed from: c */
    public final long[] f4608c;

    /* renamed from: d */
    public final a[] f4609d;

    /* renamed from: e */
    public final long f4610e;

    /* renamed from: b.l.a.a.k1.j0.a$a */
    public static final class a {

        /* renamed from: a */
        public final int f4611a;

        /* renamed from: b */
        public final Uri[] f4612b;

        /* renamed from: c */
        public final int[] f4613c;

        /* renamed from: d */
        public final long[] f4614d;

        public a() {
            C4195m.m4765F(true);
            this.f4611a = -1;
            this.f4613c = new int[0];
            this.f4612b = new Uri[0];
            this.f4614d = new long[0];
        }

        /* renamed from: a */
        public int m1837a(int i2) {
            int i3 = i2 + 1;
            while (true) {
                int[] iArr = this.f4613c;
                if (i3 >= iArr.length || iArr[i3] == 0 || iArr[i3] == 1) {
                    break;
                }
                i3++;
            }
            return i3;
        }

        /* renamed from: b */
        public boolean m1838b() {
            return this.f4611a == -1 || m1837a(-1) < this.f4611a;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || a.class != obj.getClass()) {
                return false;
            }
            a aVar = (a) obj;
            return this.f4611a == aVar.f4611a && Arrays.equals(this.f4612b, aVar.f4612b) && Arrays.equals(this.f4613c, aVar.f4613c) && Arrays.equals(this.f4614d, aVar.f4614d);
        }

        public int hashCode() {
            return Arrays.hashCode(this.f4614d) + ((Arrays.hashCode(this.f4613c) + (((this.f4611a * 31) + Arrays.hashCode(this.f4612b)) * 31)) * 31);
        }
    }

    public C2117a(long... jArr) {
        int length = jArr.length;
        this.f4607b = length;
        this.f4608c = Arrays.copyOf(jArr, length);
        this.f4609d = new a[length];
        for (int i2 = 0; i2 < length; i2++) {
            this.f4609d[i2] = new a();
        }
        this.f4610e = -9223372036854775807L;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2117a.class != obj.getClass()) {
            return false;
        }
        C2117a c2117a = (C2117a) obj;
        return this.f4607b == c2117a.f4607b && this.f4610e == c2117a.f4610e && Arrays.equals(this.f4608c, c2117a.f4608c) && Arrays.equals(this.f4609d, c2117a.f4609d);
    }

    public int hashCode() {
        return Arrays.hashCode(this.f4609d) + ((Arrays.hashCode(this.f4608c) + (((((this.f4607b * 31) + ((int) 0)) * 31) + ((int) this.f4610e)) * 31)) * 31);
    }
}
