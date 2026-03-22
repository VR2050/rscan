package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.p */
/* loaded from: classes.dex */
public final class C2324p {

    /* renamed from: a */
    public final Uri f5933a;

    /* renamed from: b */
    public final int f5934b;

    /* renamed from: c */
    @Nullable
    public final byte[] f5935c;

    /* renamed from: d */
    public final Map<String, String> f5936d;

    /* renamed from: e */
    public final long f5937e;

    /* renamed from: f */
    public final long f5938f;

    /* renamed from: g */
    public final long f5939g;

    /* renamed from: h */
    @Nullable
    public final String f5940h;

    /* renamed from: i */
    public final int f5941i;

    public C2324p(Uri uri, long j2, long j3, @Nullable String str) {
        this(uri, j2, j2, j3, str, 0);
    }

    /* renamed from: a */
    public static String m2266a(int i2) {
        if (i2 == 1) {
            return "GET";
        }
        if (i2 == 2) {
            return "POST";
        }
        if (i2 == 3) {
            return "HEAD";
        }
        throw new AssertionError(i2);
    }

    /* renamed from: b */
    public boolean m2267b(int i2) {
        return (this.f5941i & i2) == i2;
    }

    /* renamed from: c */
    public C2324p m2268c(long j2) {
        long j3 = this.f5939g;
        return m2269d(j2, j3 != -1 ? j3 - j2 : -1L);
    }

    /* renamed from: d */
    public C2324p m2269d(long j2, long j3) {
        return (j2 == 0 && this.f5939g == j3) ? this : new C2324p(this.f5933a, this.f5934b, this.f5935c, this.f5937e + j2, this.f5938f + j2, j3, this.f5940h, this.f5941i, this.f5936d);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("DataSpec[");
        m586H.append(m2266a(this.f5934b));
        m586H.append(" ");
        m586H.append(this.f5933a);
        m586H.append(", ");
        m586H.append(Arrays.toString(this.f5935c));
        m586H.append(", ");
        m586H.append(this.f5937e);
        m586H.append(", ");
        m586H.append(this.f5938f);
        m586H.append(", ");
        m586H.append(this.f5939g);
        m586H.append(", ");
        m586H.append(this.f5940h);
        m586H.append(", ");
        return C1499a.m580B(m586H, this.f5941i, "]");
    }

    public C2324p(Uri uri, long j2, long j3, long j4, @Nullable String str, int i2) {
        this(uri, 1, null, j2, j3, j4, str, i2, Collections.emptyMap());
    }

    public C2324p(Uri uri, int i2, @Nullable byte[] bArr, long j2, long j3, long j4, @Nullable String str, int i3, Map<String, String> map) {
        byte[] bArr2 = bArr;
        boolean z = true;
        C4195m.m4765F(j2 >= 0);
        C4195m.m4765F(j3 >= 0);
        if (j4 <= 0 && j4 != -1) {
            z = false;
        }
        C4195m.m4765F(z);
        this.f5933a = uri;
        this.f5934b = i2;
        this.f5935c = (bArr2 == null || bArr2.length == 0) ? null : bArr2;
        this.f5937e = j2;
        this.f5938f = j3;
        this.f5939g = j4;
        this.f5940h = str;
        this.f5941i = i3;
        this.f5936d = Collections.unmodifiableMap(new HashMap(map));
    }
}
