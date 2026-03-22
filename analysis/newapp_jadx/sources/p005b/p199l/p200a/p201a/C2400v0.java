package p005b.p199l.p200a.p201a;

import androidx.annotation.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.v0 */
/* loaded from: classes.dex */
public final class C2400v0 {

    /* renamed from: a */
    public static final C2400v0 f6332a;

    /* renamed from: b */
    public static final C2400v0 f6333b;

    /* renamed from: c */
    public final long f6334c;

    /* renamed from: d */
    public final long f6335d;

    static {
        C2400v0 c2400v0 = new C2400v0(0L, 0L);
        f6332a = c2400v0;
        C4195m.m4765F(Long.MAX_VALUE >= 0);
        C4195m.m4765F(Long.MAX_VALUE >= 0);
        C4195m.m4765F(Long.MAX_VALUE >= 0);
        C4195m.m4765F(0 >= 0);
        C4195m.m4765F(0 >= 0);
        C4195m.m4765F(Long.MAX_VALUE >= 0);
        f6333b = c2400v0;
    }

    public C2400v0(long j2, long j3) {
        C4195m.m4765F(j2 >= 0);
        C4195m.m4765F(j3 >= 0);
        this.f6334c = j2;
        this.f6335d = j3;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2400v0.class != obj.getClass()) {
            return false;
        }
        C2400v0 c2400v0 = (C2400v0) obj;
        return this.f6334c == c2400v0.f6334c && this.f6335d == c2400v0.f6335d;
    }

    public int hashCode() {
        return (((int) this.f6334c) * 31) + ((int) this.f6335d);
    }
}
