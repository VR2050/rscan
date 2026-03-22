package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import android.net.Uri;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2153j;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.l0.k.i */
/* loaded from: classes.dex */
public abstract class AbstractC2152i {

    /* renamed from: a */
    public final Format f4823a;

    /* renamed from: b */
    public final String f4824b;

    /* renamed from: c */
    public final long f4825c;

    /* renamed from: d */
    public final List<C2147d> f4826d;

    /* renamed from: e */
    public final C2151h f4827e;

    /* renamed from: b.l.a.a.k1.l0.k.i$b */
    public static class b extends AbstractC2152i implements InterfaceC2139f {

        /* renamed from: f */
        public final AbstractC2153j.a f4828f;

        public b(long j2, Format format, String str, AbstractC2153j.a aVar, @Nullable List<C2147d> list) {
            super(j2, format, str, aVar, list, null);
            this.f4828f = aVar;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
        /* renamed from: a */
        public long mo1867a(long j2) {
            return this.f4828f.m1922c(j2);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
        /* renamed from: b */
        public long mo1868b(long j2, long j3) {
            AbstractC2153j.a aVar = this.f4828f;
            List<AbstractC2153j.d> list = aVar.f4837f;
            if (list != null) {
                return (list.get((int) (j2 - aVar.f4835d)).f4843b * 1000000) / aVar.f4833b;
            }
            int mo1921b = aVar.mo1921b(j3);
            return (mo1921b == -1 || j2 != (aVar.f4835d + ((long) mo1921b)) - 1) ? (aVar.f4836e * 1000000) / aVar.f4833b : j3 - aVar.m1922c(j2);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
        /* renamed from: c */
        public C2151h mo1869c(long j2) {
            return this.f4828f.mo1923d(this, j2);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
        /* renamed from: d */
        public long mo1870d(long j2, long j3) {
            long j4;
            AbstractC2153j.a aVar = this.f4828f;
            long j5 = aVar.f4835d;
            long mo1921b = aVar.mo1921b(j3);
            if (mo1921b == 0) {
                return j5;
            }
            if (aVar.f4837f == null) {
                j4 = (j2 / ((aVar.f4836e * 1000000) / aVar.f4833b)) + aVar.f4835d;
                if (j4 < j5) {
                    return j5;
                }
                if (mo1921b != -1) {
                    return Math.min(j4, (j5 + mo1921b) - 1);
                }
            } else {
                long j6 = (mo1921b + j5) - 1;
                j4 = j5;
                while (j4 <= j6) {
                    long j7 = ((j6 - j4) / 2) + j4;
                    long m1922c = aVar.m1922c(j7);
                    if (m1922c < j2) {
                        j4 = j7 + 1;
                    } else {
                        if (m1922c <= j2) {
                            return j7;
                        }
                        j6 = j7 - 1;
                    }
                }
                if (j4 != j5) {
                    return j6;
                }
            }
            return j4;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
        /* renamed from: e */
        public boolean mo1871e() {
            return this.f4828f.mo1924e();
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
        /* renamed from: f */
        public long mo1872f() {
            return this.f4828f.f4835d;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
        /* renamed from: g */
        public int mo1873g(long j2) {
            return this.f4828f.mo1921b(j2);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2152i
        @Nullable
        /* renamed from: h */
        public String mo1917h() {
            return null;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2152i
        /* renamed from: i */
        public InterfaceC2139f mo1918i() {
            return this;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2152i
        @Nullable
        /* renamed from: j */
        public C2151h mo1919j() {
            return null;
        }
    }

    /* renamed from: b.l.a.a.k1.l0.k.i$c */
    public static class c extends AbstractC2152i {

        /* renamed from: f */
        @Nullable
        public final String f4829f;

        /* renamed from: g */
        @Nullable
        public final C2151h f4830g;

        /* renamed from: h */
        @Nullable
        public final C2154k f4831h;

        public c(long j2, Format format, String str, AbstractC2153j.e eVar, @Nullable List<C2147d> list, @Nullable String str2, long j3) {
            super(j2, format, str, eVar, list, null);
            Uri.parse(str);
            long j4 = eVar.f4845e;
            C2151h c2151h = j4 <= 0 ? null : new C2151h(null, eVar.f4844d, j4);
            this.f4830g = c2151h;
            this.f4829f = str2;
            this.f4831h = c2151h == null ? new C2154k(new C2151h(null, 0L, j3)) : null;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2152i
        @Nullable
        /* renamed from: h */
        public String mo1917h() {
            return this.f4829f;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2152i
        @Nullable
        /* renamed from: i */
        public InterfaceC2139f mo1918i() {
            return this.f4831h;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2152i
        @Nullable
        /* renamed from: j */
        public C2151h mo1919j() {
            return this.f4830g;
        }
    }

    public AbstractC2152i(long j2, Format format, String str, AbstractC2153j abstractC2153j, List list, a aVar) {
        this.f4823a = format;
        this.f4824b = str;
        this.f4826d = list == null ? Collections.emptyList() : Collections.unmodifiableList(list);
        this.f4827e = abstractC2153j.mo1920a(this);
        this.f4825c = C2344d0.m2314F(abstractC2153j.f4834c, 1000000L, abstractC2153j.f4833b);
    }

    @Nullable
    /* renamed from: h */
    public abstract String mo1917h();

    @Nullable
    /* renamed from: i */
    public abstract InterfaceC2139f mo1918i();

    @Nullable
    /* renamed from: j */
    public abstract C2151h mo1919j();
}
