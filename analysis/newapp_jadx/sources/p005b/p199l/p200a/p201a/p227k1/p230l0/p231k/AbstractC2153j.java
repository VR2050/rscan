package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.List;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.l0.k.j */
/* loaded from: classes.dex */
public abstract class AbstractC2153j {

    /* renamed from: a */
    @Nullable
    public final C2151h f4832a;

    /* renamed from: b */
    public final long f4833b;

    /* renamed from: c */
    public final long f4834c;

    /* renamed from: b.l.a.a.k1.l0.k.j$a */
    public static abstract class a extends AbstractC2153j {

        /* renamed from: d */
        public final long f4835d;

        /* renamed from: e */
        public final long f4836e;

        /* renamed from: f */
        @Nullable
        public final List<d> f4837f;

        public a(@Nullable C2151h c2151h, long j2, long j3, long j4, long j5, @Nullable List<d> list) {
            super(c2151h, j2, j3);
            this.f4835d = j4;
            this.f4836e = j5;
            this.f4837f = list;
        }

        /* renamed from: b */
        public abstract int mo1921b(long j2);

        /* renamed from: c */
        public final long m1922c(long j2) {
            List<d> list = this.f4837f;
            return C2344d0.m2314F(list != null ? list.get((int) (j2 - this.f4835d)).f4842a - this.f4834c : (j2 - this.f4835d) * this.f4836e, 1000000L, this.f4833b);
        }

        /* renamed from: d */
        public abstract C2151h mo1923d(AbstractC2152i abstractC2152i, long j2);

        /* renamed from: e */
        public boolean mo1924e() {
            return this.f4837f != null;
        }
    }

    /* renamed from: b.l.a.a.k1.l0.k.j$b */
    public static class b extends a {

        /* renamed from: g */
        @Nullable
        public final List<C2151h> f4838g;

        public b(C2151h c2151h, long j2, long j3, long j4, long j5, @Nullable List<d> list, @Nullable List<C2151h> list2) {
            super(c2151h, j2, j3, j4, j5, list);
            this.f4838g = list2;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2153j.a
        /* renamed from: b */
        public int mo1921b(long j2) {
            return this.f4838g.size();
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2153j.a
        /* renamed from: d */
        public C2151h mo1923d(AbstractC2152i abstractC2152i, long j2) {
            return this.f4838g.get((int) (j2 - this.f4835d));
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2153j.a
        /* renamed from: e */
        public boolean mo1924e() {
            return true;
        }
    }

    /* renamed from: b.l.a.a.k1.l0.k.j$c */
    public static class c extends a {

        /* renamed from: g */
        @Nullable
        public final C2155l f4839g;

        /* renamed from: h */
        @Nullable
        public final C2155l f4840h;

        /* renamed from: i */
        public final long f4841i;

        public c(C2151h c2151h, long j2, long j3, long j4, long j5, long j6, @Nullable List<d> list, @Nullable C2155l c2155l, @Nullable C2155l c2155l2) {
            super(c2151h, j2, j3, j4, j6, list);
            this.f4839g = c2155l;
            this.f4840h = c2155l2;
            this.f4841i = j5;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2153j
        @Nullable
        /* renamed from: a */
        public C2151h mo1920a(AbstractC2152i abstractC2152i) {
            C2155l c2155l = this.f4839g;
            if (c2155l == null) {
                return this.f4832a;
            }
            Format format = abstractC2152i.f4823a;
            return new C2151h(c2155l.m1925a(format.f9237c, 0L, format.f9241h, 0L), 0L, -1L);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2153j.a
        /* renamed from: b */
        public int mo1921b(long j2) {
            List<d> list = this.f4837f;
            if (list != null) {
                return list.size();
            }
            long j3 = this.f4841i;
            if (j3 != -1) {
                return (int) ((j3 - this.f4835d) + 1);
            }
            if (j2 == -9223372036854775807L) {
                return -1;
            }
            long j4 = (this.f4836e * 1000000) / this.f4833b;
            int i2 = C2344d0.f6035a;
            return (int) (((j2 + j4) - 1) / j4);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2153j.a
        /* renamed from: d */
        public C2151h mo1923d(AbstractC2152i abstractC2152i, long j2) {
            List<d> list = this.f4837f;
            long j3 = list != null ? list.get((int) (j2 - this.f4835d)).f4842a : (j2 - this.f4835d) * this.f4836e;
            C2155l c2155l = this.f4840h;
            Format format = abstractC2152i.f4823a;
            return new C2151h(c2155l.m1925a(format.f9237c, j2, format.f9241h, j3), 0L, -1L);
        }
    }

    /* renamed from: b.l.a.a.k1.l0.k.j$d */
    public static class d {

        /* renamed from: a */
        public final long f4842a;

        /* renamed from: b */
        public final long f4843b;

        public d(long j2, long j3) {
            this.f4842a = j2;
            this.f4843b = j3;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || d.class != obj.getClass()) {
                return false;
            }
            d dVar = (d) obj;
            return this.f4842a == dVar.f4842a && this.f4843b == dVar.f4843b;
        }

        public int hashCode() {
            return (((int) this.f4842a) * 31) + ((int) this.f4843b);
        }
    }

    public AbstractC2153j(@Nullable C2151h c2151h, long j2, long j3) {
        this.f4832a = c2151h;
        this.f4833b = j2;
        this.f4834c = j3;
    }

    @Nullable
    /* renamed from: a */
    public C2151h mo1920a(AbstractC2152i abstractC2152i) {
        return this.f4832a;
    }

    /* renamed from: b.l.a.a.k1.l0.k.j$e */
    public static class e extends AbstractC2153j {

        /* renamed from: d */
        public final long f4844d;

        /* renamed from: e */
        public final long f4845e;

        public e() {
            super(null, 1L, 0L);
            this.f4844d = 0L;
            this.f4845e = 0L;
        }

        public e(@Nullable C2151h c2151h, long j2, long j3, long j4, long j5) {
            super(c2151h, j2, j3);
            this.f4844d = j4;
            this.f4845e = j5;
        }
    }
}
