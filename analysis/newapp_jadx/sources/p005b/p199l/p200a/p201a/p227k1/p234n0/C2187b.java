package p005b.p199l.p200a.p201a.p227k1.p234n0;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1984d;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1989i;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1990j;
import p005b.p199l.p200a.p201a.p227k1.C2192o;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2120b;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2122d;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2123e;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2124f;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2127i;
import p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2131m;
import p005b.p199l.p200a.p201a.p227k1.p234n0.InterfaceC2188c;
import p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2190a;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2283b0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.n0.b */
/* loaded from: classes.dex */
public class C2187b implements InterfaceC2188c {

    /* renamed from: a */
    public final InterfaceC2283b0 f5132a;

    /* renamed from: b */
    public final int f5133b;

    /* renamed from: c */
    public final C2123e[] f5134c;

    /* renamed from: d */
    public final InterfaceC2321m f5135d;

    /* renamed from: e */
    public InterfaceC2257f f5136e;

    /* renamed from: f */
    public C2190a f5137f;

    /* renamed from: g */
    public int f5138g;

    /* renamed from: h */
    public IOException f5139h;

    /* renamed from: b.l.a.a.k1.n0.b$a */
    public static final class a implements InterfaceC2188c.a {

        /* renamed from: a */
        public final InterfaceC2321m.a f5140a;

        public a(InterfaceC2321m.a aVar) {
            this.f5140a = aVar;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.InterfaceC2188c.a
        /* renamed from: a */
        public InterfaceC2188c mo2004a(InterfaceC2283b0 interfaceC2283b0, C2190a c2190a, int i2, InterfaceC2257f interfaceC2257f, @Nullable InterfaceC2291f0 interfaceC2291f0) {
            InterfaceC2321m createDataSource = this.f5140a.createDataSource();
            if (interfaceC2291f0 != null) {
                createDataSource.addTransferListener(interfaceC2291f0);
            }
            return new C2187b(interfaceC2283b0, c2190a, i2, interfaceC2257f, createDataSource);
        }
    }

    /* renamed from: b.l.a.a.k1.n0.b$b */
    public static final class b extends AbstractC2120b {
        public b(C2190a.b bVar, int i2, int i3) {
            super(i3, bVar.f5176k - 1);
        }
    }

    public C2187b(InterfaceC2283b0 interfaceC2283b0, C2190a c2190a, int i2, InterfaceC2257f interfaceC2257f, InterfaceC2321m interfaceC2321m) {
        this.f5132a = interfaceC2283b0;
        this.f5137f = c2190a;
        this.f5133b = i2;
        this.f5136e = interfaceC2257f;
        this.f5135d = interfaceC2321m;
        C2190a.b bVar = c2190a.f5160f[i2];
        this.f5134c = new C2123e[interfaceC2257f.length()];
        int i3 = 0;
        while (i3 < this.f5134c.length) {
            int mo2153g = interfaceC2257f.mo2153g(i3);
            Format format = bVar.f5175j[mo2153g];
            C1990j[] c1990jArr = format.f9248o != null ? c2190a.f5159e.f5165c : null;
            int i4 = bVar.f5166a;
            int i5 = i3;
            this.f5134c[i5] = new C2123e(new C1984d(3, null, new C1989i(mo2153g, i4, bVar.f5168c, -9223372036854775807L, c2190a.f5161g, format, 0, c1990jArr, i4 == 2 ? 4 : 0, null, null), Collections.emptyList()), bVar.f5166a, format);
            i3 = i5 + 1;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: a */
    public void mo1854a() {
        IOException iOException = this.f5139h;
        if (iOException != null) {
            throw iOException;
        }
        this.f5132a.mo2180a();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.InterfaceC2188c
    /* renamed from: b */
    public void mo2002b(InterfaceC2257f interfaceC2257f) {
        this.f5136e = interfaceC2257f;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p234n0.InterfaceC2188c
    /* renamed from: c */
    public void mo2003c(C2190a c2190a) {
        C2190a.b[] bVarArr = this.f5137f.f5160f;
        int i2 = this.f5133b;
        C2190a.b bVar = bVarArr[i2];
        int i3 = bVar.f5176k;
        C2190a.b bVar2 = c2190a.f5160f[i2];
        if (i3 == 0 || bVar2.f5176k == 0) {
            this.f5138g += i3;
        } else {
            int i4 = i3 - 1;
            long m2005a = bVar.m2005a(i4) + bVar.f5180o[i4];
            long j2 = bVar2.f5180o[0];
            if (m2005a <= j2) {
                this.f5138g += i3;
            } else {
                this.f5138g = bVar.m2006b(j2) + this.f5138g;
            }
        }
        this.f5137f = c2190a;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: d */
    public boolean mo1855d(AbstractC2122d abstractC2122d, boolean z, Exception exc, long j2) {
        if (z && j2 != -9223372036854775807L) {
            InterfaceC2257f interfaceC2257f = this.f5136e;
            if (interfaceC2257f.mo2150c(interfaceC2257f.mo2154i(abstractC2122d.f4625c), j2)) {
                return true;
            }
        }
        return false;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: e */
    public long mo1856e(long j2, C2400v0 c2400v0) {
        C2190a.b bVar = this.f5137f.f5160f[this.f5133b];
        int m2326d = C2344d0.m2326d(bVar.f5180o, j2, true, true);
        long[] jArr = bVar.f5180o;
        long j3 = jArr[m2326d];
        return C2344d0.m2313E(j2, c2400v0, j3, (j3 >= j2 || m2326d >= bVar.f5176k - 1) ? j3 : jArr[m2326d + 1]);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: g */
    public int mo1857g(long j2, List<? extends AbstractC2130l> list) {
        return (this.f5139h != null || this.f5136e.length() < 2) ? list.size() : this.f5136e.mo2146h(j2, list);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: h */
    public void mo1858h(AbstractC2122d abstractC2122d) {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: i */
    public final void mo1859i(long j2, long j3, List<? extends AbstractC2130l> list, C2124f c2124f) {
        int mo1860c;
        long m2005a;
        if (this.f5139h != null) {
            return;
        }
        C2190a.b bVar = this.f5137f.f5160f[this.f5133b];
        if (bVar.f5176k == 0) {
            c2124f.f4648b = !r1.f5158d;
            return;
        }
        if (list.isEmpty()) {
            mo1860c = C2344d0.m2326d(bVar.f5180o, j3, true, true);
        } else {
            mo1860c = (int) (((AbstractC2130l) C1499a.m611d(list, 1)).mo1860c() - this.f5138g);
            if (mo1860c < 0) {
                this.f5139h = new C2192o();
                return;
            }
        }
        int i2 = mo1860c;
        if (i2 >= bVar.f5176k) {
            c2124f.f4648b = !this.f5137f.f5158d;
            return;
        }
        long j4 = j3 - j2;
        C2190a c2190a = this.f5137f;
        if (c2190a.f5158d) {
            C2190a.b bVar2 = c2190a.f5160f[this.f5133b];
            int i3 = bVar2.f5176k - 1;
            m2005a = (bVar2.m2005a(i3) + bVar2.f5180o[i3]) - j2;
        } else {
            m2005a = -9223372036854775807L;
        }
        int length = this.f5136e.length();
        InterfaceC2131m[] interfaceC2131mArr = new InterfaceC2131m[length];
        for (int i4 = 0; i4 < length; i4++) {
            interfaceC2131mArr[i4] = new b(bVar, this.f5136e.mo2153g(i4), i2);
        }
        this.f5136e.mo1942j(j2, j4, m2005a, list, interfaceC2131mArr);
        long j5 = bVar.f5180o[i2];
        long m2005a2 = bVar.m2005a(i2) + j5;
        long j6 = list.isEmpty() ? j3 : -9223372036854775807L;
        int i5 = this.f5138g + i2;
        int mo1941b = this.f5136e.mo1941b();
        C2123e c2123e = this.f5134c[mo1941b];
        int mo2153g = this.f5136e.mo2153g(mo1941b);
        C4195m.m4771I(bVar.f5175j != null);
        C4195m.m4771I(bVar.f5179n != null);
        C4195m.m4771I(i2 < bVar.f5179n.size());
        String num = Integer.toString(bVar.f5175j[mo2153g].f9241h);
        String l2 = bVar.f5179n.get(i2).toString();
        c2124f.f4647a = new C2127i(this.f5135d, new C2324p(C2354n.m2514s1(bVar.f5177l, bVar.f5178m.replace("{bitrate}", num).replace("{Bitrate}", num).replace("{start time}", l2).replace("{start_time}", l2)), 0L, -1L, null), this.f5136e.mo2156l(), this.f5136e.mo1943m(), this.f5136e.mo1944o(), j5, m2005a2, j6, -9223372036854775807L, i5, 1, j5, c2123e);
    }
}
