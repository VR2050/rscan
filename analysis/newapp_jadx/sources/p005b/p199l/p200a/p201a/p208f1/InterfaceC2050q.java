package p005b.p199l.p200a.p201a.p208f1;

import androidx.annotation.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.a.a.f1.q */
/* loaded from: classes.dex */
public interface InterfaceC2050q {

    /* renamed from: b.l.a.a.f1.q$b */
    public static class b implements InterfaceC2050q {

        /* renamed from: a */
        public final long f4190a;

        /* renamed from: b */
        public final a f4191b;

        public b(long j2, long j3) {
            this.f4190a = j2;
            this.f4191b = new a(j3 == 0 ? C2051r.f4192a : new C2051r(0L, j3));
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: c */
        public boolean mo1462c() {
            return false;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: g */
        public a mo1463g(long j2) {
            return this.f4191b;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: i */
        public long mo1464i() {
            return this.f4190a;
        }
    }

    /* renamed from: c */
    boolean mo1462c();

    /* renamed from: g */
    a mo1463g(long j2);

    /* renamed from: i */
    long mo1464i();

    /* renamed from: b.l.a.a.f1.q$a */
    public static final class a {

        /* renamed from: a */
        public final C2051r f4188a;

        /* renamed from: b */
        public final C2051r f4189b;

        public a(C2051r c2051r) {
            this.f4188a = c2051r;
            this.f4189b = c2051r;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || a.class != obj.getClass()) {
                return false;
            }
            a aVar = (a) obj;
            return this.f4188a.equals(aVar.f4188a) && this.f4189b.equals(aVar.f4189b);
        }

        public int hashCode() {
            return this.f4189b.hashCode() + (this.f4188a.hashCode() * 31);
        }

        public String toString() {
            String sb;
            StringBuilder m586H = C1499a.m586H("[");
            m586H.append(this.f4188a);
            if (this.f4188a.equals(this.f4189b)) {
                sb = "";
            } else {
                StringBuilder m586H2 = C1499a.m586H(", ");
                m586H2.append(this.f4189b);
                sb = m586H2.toString();
            }
            return C1499a.m582D(m586H, sb, "]");
        }

        public a(C2051r c2051r, C2051r c2051r2) {
            this.f4188a = c2051r;
            this.f4189b = c2051r2;
        }
    }
}
