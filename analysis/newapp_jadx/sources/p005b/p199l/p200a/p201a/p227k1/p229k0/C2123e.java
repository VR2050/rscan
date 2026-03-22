package p005b.p199l.p200a.p201a.p227k1.p229k0;

import android.util.SparseArray;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2036g;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.k0.e */
/* loaded from: classes.dex */
public final class C2123e implements InterfaceC2042i {

    /* renamed from: c */
    public final InterfaceC2041h f4631c;

    /* renamed from: e */
    public final int f4632e;

    /* renamed from: f */
    public final Format f4633f;

    /* renamed from: g */
    public final SparseArray<a> f4634g = new SparseArray<>();

    /* renamed from: h */
    public boolean f4635h;

    /* renamed from: i */
    public b f4636i;

    /* renamed from: j */
    public long f4637j;

    /* renamed from: k */
    public InterfaceC2050q f4638k;

    /* renamed from: l */
    public Format[] f4639l;

    /* renamed from: b.l.a.a.k1.k0.e$a */
    public static final class a implements InterfaceC2052s {

        /* renamed from: a */
        public final int f4640a;

        /* renamed from: b */
        public final int f4641b;

        /* renamed from: c */
        public final Format f4642c;

        /* renamed from: d */
        public final C2036g f4643d = new C2036g();

        /* renamed from: e */
        public Format f4644e;

        /* renamed from: f */
        public InterfaceC2052s f4645f;

        /* renamed from: g */
        public long f4646g;

        public a(int i2, int i3, Format format) {
            this.f4640a = i2;
            this.f4641b = i3;
            this.f4642c = format;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: a */
        public int mo1612a(C2003e c2003e, int i2, boolean z) {
            return this.f4645f.mo1612a(c2003e, i2, z);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: b */
        public void mo1613b(C2360t c2360t, int i2) {
            this.f4645f.mo1613b(c2360t, i2);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: c */
        public void mo1614c(long j2, int i2, int i3, int i4, InterfaceC2052s.a aVar) {
            long j3 = this.f4646g;
            if (j3 != -9223372036854775807L && j2 >= j3) {
                this.f4645f = this.f4643d;
            }
            this.f4645f.mo1614c(j2, i2, i3, i4, aVar);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: d */
        public void mo1615d(Format format) {
            Format format2 = this.f4642c;
            if (format2 != null) {
                format = format.m4046q(format2);
            }
            this.f4644e = format;
            this.f4645f.mo1615d(format);
        }

        /* renamed from: e */
        public void m1842e(b bVar, long j2) {
            if (bVar == null) {
                this.f4645f = this.f4643d;
                return;
            }
            this.f4646g = j2;
            InterfaceC2052s m1840b = ((C2121c) bVar).m1840b(this.f4640a, this.f4641b);
            this.f4645f = m1840b;
            Format format = this.f4644e;
            if (format != null) {
                m1840b.mo1615d(format);
            }
        }
    }

    /* renamed from: b.l.a.a.k1.k0.e$b */
    public interface b {
    }

    public C2123e(InterfaceC2041h interfaceC2041h, int i2, Format format) {
        this.f4631c = interfaceC2041h;
        this.f4632e = i2;
        this.f4633f = format;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: a */
    public void mo1623a(InterfaceC2050q interfaceC2050q) {
        this.f4638k = interfaceC2050q;
    }

    /* renamed from: b */
    public void m1841b(@Nullable b bVar, long j2, long j3) {
        this.f4636i = bVar;
        this.f4637j = j3;
        if (!this.f4635h) {
            this.f4631c.mo1480e(this);
            if (j2 != -9223372036854775807L) {
                this.f4631c.mo1481f(0L, j2);
            }
            this.f4635h = true;
            return;
        }
        InterfaceC2041h interfaceC2041h = this.f4631c;
        if (j2 == -9223372036854775807L) {
            j2 = 0;
        }
        interfaceC2041h.mo1481f(0L, j2);
        for (int i2 = 0; i2 < this.f4634g.size(); i2++) {
            this.f4634g.valueAt(i2).m1842e(bVar, j3);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: o */
    public void mo1624o() {
        Format[] formatArr = new Format[this.f4634g.size()];
        for (int i2 = 0; i2 < this.f4634g.size(); i2++) {
            formatArr[i2] = this.f4634g.valueAt(i2).f4644e;
        }
        this.f4639l = formatArr;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: t */
    public InterfaceC2052s mo1625t(int i2, int i3) {
        a aVar = this.f4634g.get(i2);
        if (aVar == null) {
            C4195m.m4771I(this.f4639l == null);
            aVar = new a(i2, i3, i3 == this.f4632e ? this.f4633f : null);
            aVar.m1842e(this.f4636i, this.f4637j);
            this.f4634g.put(i2, aVar);
        }
        return aVar;
    }
}
