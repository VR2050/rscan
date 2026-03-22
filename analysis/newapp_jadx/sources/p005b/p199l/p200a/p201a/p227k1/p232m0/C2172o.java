package p005b.p199l.p200a.p201a.p227k1.p232m0;

import android.net.Uri;
import android.os.Handler;
import android.util.SparseIntArray;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.emsg.EventMessage;
import com.google.android.exoplayer2.metadata.id3.PrivFrame;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.checkerframework.checker.nullness.qual.EnsuresNonNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2036g;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p220h1.p221g.C2084a;
import p005b.p199l.p200a.p201a.p220h1.p223i.C2088b;
import p005b.p199l.p200a.p201a.p227k1.C2105d0;
import p005b.p199l.p200a.p201a.p227k1.C2192o;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2122d;
import p005b.p199l.p200a.p201a.p227k1.p232m0.C2165h;
import p005b.p199l.p200a.p201a.p227k1.p232m0.C2172o;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2178c;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2180e;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.C2331w;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.m0.o */
/* loaded from: classes.dex */
public final class C2172o implements C2281a0.b<AbstractC2122d>, C2281a0.f, InterfaceC2109f0, InterfaceC2042i, C2105d0.b {

    /* renamed from: c */
    public static final Set<Integer> f4943c = Collections.unmodifiableSet(new HashSet(Arrays.asList(1, 2, 4)));

    /* renamed from: A */
    public InterfaceC2052s f4944A;

    /* renamed from: B */
    public int f4945B;

    /* renamed from: C */
    public int f4946C;

    /* renamed from: D */
    public boolean f4947D;

    /* renamed from: E */
    public boolean f4948E;

    /* renamed from: F */
    public int f4949F;

    /* renamed from: G */
    public Format f4950G;

    /* renamed from: H */
    @Nullable
    public Format f4951H;

    /* renamed from: I */
    public boolean f4952I;

    /* renamed from: J */
    public TrackGroupArray f4953J;

    /* renamed from: K */
    public Set<TrackGroup> f4954K;

    /* renamed from: L */
    public int[] f4955L;

    /* renamed from: M */
    public int f4956M;

    /* renamed from: N */
    public boolean f4957N;

    /* renamed from: O */
    public boolean[] f4958O;

    /* renamed from: P */
    public boolean[] f4959P;

    /* renamed from: Q */
    public long f4960Q;

    /* renamed from: R */
    public long f4961R;

    /* renamed from: S */
    public boolean f4962S;

    /* renamed from: T */
    public boolean f4963T;

    /* renamed from: U */
    public boolean f4964U;

    /* renamed from: V */
    public boolean f4965V;

    /* renamed from: W */
    public long f4966W;

    /* renamed from: X */
    @Nullable
    public DrmInitData f4967X;

    /* renamed from: Y */
    public int f4968Y;

    /* renamed from: e */
    public final int f4969e;

    /* renamed from: f */
    public final a f4970f;

    /* renamed from: g */
    public final C2165h f4971g;

    /* renamed from: h */
    public final InterfaceC2288e f4972h;

    /* renamed from: i */
    @Nullable
    public final Format f4973i;

    /* renamed from: j */
    public final InterfaceC1954e<?> f4974j;

    /* renamed from: k */
    public final InterfaceC2334z f4975k;

    /* renamed from: m */
    public final InterfaceC2203z.a f4977m;

    /* renamed from: n */
    public final int f4978n;

    /* renamed from: p */
    public final ArrayList<C2169l> f4980p;

    /* renamed from: q */
    public final List<C2169l> f4981q;

    /* renamed from: r */
    public final Runnable f4982r;

    /* renamed from: s */
    public final Runnable f4983s;

    /* renamed from: t */
    public final Handler f4984t;

    /* renamed from: u */
    public final ArrayList<C2171n> f4985u;

    /* renamed from: v */
    public final Map<String, DrmInitData> f4986v;

    /* renamed from: w */
    public c[] f4987w;

    /* renamed from: y */
    public Set<Integer> f4989y;

    /* renamed from: z */
    public SparseIntArray f4990z;

    /* renamed from: l */
    public final C2281a0 f4976l = new C2281a0("Loader:HlsSampleStreamWrapper");

    /* renamed from: o */
    public final C2165h.b f4979o = new C2165h.b();

    /* renamed from: x */
    public int[] f4988x = new int[0];

    /* renamed from: b.l.a.a.k1.m0.o$a */
    public interface a extends InterfaceC2109f0.a<C2172o> {
    }

    /* renamed from: b.l.a.a.k1.m0.o$b */
    public static class b implements InterfaceC2052s {

        /* renamed from: a */
        public static final Format f4991a = Format.m4027D(null, "application/id3", Long.MAX_VALUE);

        /* renamed from: b */
        public static final Format f4992b = Format.m4027D(null, "application/x-emsg", Long.MAX_VALUE);

        /* renamed from: c */
        public final C2084a f4993c = new C2084a();

        /* renamed from: d */
        public final InterfaceC2052s f4994d;

        /* renamed from: e */
        public final Format f4995e;

        /* renamed from: f */
        public Format f4996f;

        /* renamed from: g */
        public byte[] f4997g;

        /* renamed from: h */
        public int f4998h;

        public b(InterfaceC2052s interfaceC2052s, int i2) {
            this.f4994d = interfaceC2052s;
            if (i2 == 1) {
                this.f4995e = f4991a;
            } else {
                if (i2 != 3) {
                    throw new IllegalArgumentException(C1499a.m626l("Unknown metadataType: ", i2));
                }
                this.f4995e = f4992b;
            }
            this.f4997g = new byte[0];
            this.f4998h = 0;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: a */
        public int mo1612a(C2003e c2003e, int i2, boolean z) {
            int i3 = this.f4998h + i2;
            byte[] bArr = this.f4997g;
            if (bArr.length < i3) {
                this.f4997g = Arrays.copyOf(bArr, (i3 / 2) + i3);
            }
            int m1566f = c2003e.m1566f(this.f4997g, this.f4998h, i2);
            if (m1566f != -1) {
                this.f4998h += m1566f;
                return m1566f;
            }
            if (z) {
                return -1;
            }
            throw new EOFException();
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: b */
        public void mo1613b(C2360t c2360t, int i2) {
            int i3 = this.f4998h + i2;
            byte[] bArr = this.f4997g;
            if (bArr.length < i3) {
                this.f4997g = Arrays.copyOf(bArr, (i3 / 2) + i3);
            }
            c2360t.m2572d(this.f4997g, this.f4998h, i2);
            this.f4998h += i2;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: c */
        public void mo1614c(long j2, int i2, int i3, int i4, @Nullable InterfaceC2052s.a aVar) {
            Objects.requireNonNull(this.f4996f);
            int i5 = this.f4998h - i4;
            C2360t c2360t = new C2360t(Arrays.copyOfRange(this.f4997g, i5 - i3, i5));
            byte[] bArr = this.f4997g;
            System.arraycopy(bArr, i5, bArr, 0, i4);
            this.f4998h = i4;
            if (!C2344d0.m2323a(this.f4996f.f9245l, this.f4995e.f9245l)) {
                if (!"application/x-emsg".equals(this.f4996f.f9245l)) {
                    String str = this.f4996f.f9245l;
                    return;
                }
                EventMessage m1709b = this.f4993c.m1709b(c2360t);
                Format mo4051d = m1709b.mo4051d();
                if (!(mo4051d != null && C2344d0.m2323a(this.f4995e.f9245l, mo4051d.f9245l))) {
                    String.format("Ignoring EMSG. Expected it to contain wrapped %s but actual wrapped format: %s", this.f4995e.f9245l, m1709b.mo4051d());
                    return;
                } else {
                    byte[] bArr2 = m1709b.mo4051d() != null ? m1709b.f9280j : null;
                    Objects.requireNonNull(bArr2);
                    c2360t = new C2360t(bArr2);
                }
            }
            int m2569a = c2360t.m2569a();
            this.f4994d.mo1613b(c2360t, m2569a);
            this.f4994d.mo1614c(j2, i2, m2569a, i4, aVar);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
        /* renamed from: d */
        public void mo1615d(Format format) {
            this.f4996f = format;
            this.f4994d.mo1615d(this.f4995e);
        }
    }

    /* renamed from: b.l.a.a.k1.m0.o$c */
    public static final class c extends C2105d0 {

        /* renamed from: E */
        public final Map<String, DrmInitData> f4999E;

        /* renamed from: F */
        @Nullable
        public DrmInitData f5000F;

        public c(InterfaceC2288e interfaceC2288e, InterfaceC1954e<?> interfaceC1954e, Map<String, DrmInitData> map) {
            super(interfaceC2288e, interfaceC1954e);
            this.f4999E = map;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.C2105d0
        /* renamed from: m */
        public Format mo1817m(Format format) {
            DrmInitData drmInitData;
            DrmInitData drmInitData2 = this.f5000F;
            if (drmInitData2 == null) {
                drmInitData2 = format.f9248o;
            }
            if (drmInitData2 != null && (drmInitData = this.f4999E.get(drmInitData2.f9262f)) != null) {
                drmInitData2 = drmInitData;
            }
            Metadata metadata = format.f9243j;
            if (metadata != null) {
                int length = metadata.f9273c.length;
                int i2 = 0;
                int i3 = 0;
                while (true) {
                    if (i3 >= length) {
                        i3 = -1;
                        break;
                    }
                    Metadata.Entry entry = metadata.f9273c[i3];
                    if ((entry instanceof PrivFrame) && "com.apple.streaming.transportStreamTimestamp".equals(((PrivFrame) entry).f9333e)) {
                        break;
                    }
                    i3++;
                }
                if (i3 != -1) {
                    if (length != 1) {
                        Metadata.Entry[] entryArr = new Metadata.Entry[length - 1];
                        while (i2 < length) {
                            if (i2 != i3) {
                                entryArr[i2 < i3 ? i2 : i2 - 1] = metadata.f9273c[i2];
                            }
                            i2++;
                        }
                        metadata = new Metadata(entryArr);
                    }
                }
                return super.mo1817m(format.m4042b(drmInitData2, metadata));
            }
            metadata = null;
            return super.mo1817m(format.m4042b(drmInitData2, metadata));
        }
    }

    public C2172o(int i2, a aVar, C2165h c2165h, Map<String, DrmInitData> map, InterfaceC2288e interfaceC2288e, long j2, @Nullable Format format, InterfaceC1954e<?> interfaceC1954e, InterfaceC2334z interfaceC2334z, InterfaceC2203z.a aVar2, int i3) {
        this.f4969e = i2;
        this.f4970f = aVar;
        this.f4971g = c2165h;
        this.f4986v = map;
        this.f4972h = interfaceC2288e;
        this.f4973i = format;
        this.f4974j = interfaceC1954e;
        this.f4975k = interfaceC2334z;
        this.f4977m = aVar2;
        this.f4978n = i3;
        Set<Integer> set = f4943c;
        this.f4989y = new HashSet(set.size());
        this.f4990z = new SparseIntArray(set.size());
        this.f4987w = new c[0];
        this.f4959P = new boolean[0];
        this.f4958O = new boolean[0];
        ArrayList<C2169l> arrayList = new ArrayList<>();
        this.f4980p = arrayList;
        this.f4981q = Collections.unmodifiableList(arrayList);
        this.f4985u = new ArrayList<>();
        this.f4982r = new Runnable() { // from class: b.l.a.a.k1.m0.b
            @Override // java.lang.Runnable
            public final void run() {
                C2172o.this.m1958B();
            }
        };
        this.f4983s = new Runnable() { // from class: b.l.a.a.k1.m0.a
            @Override // java.lang.Runnable
            public final void run() {
                C2172o c2172o = C2172o.this;
                c2172o.f4947D = true;
                c2172o.m1958B();
            }
        };
        this.f4984t = new Handler();
        this.f4960Q = j2;
        this.f4961R = j2;
    }

    /* renamed from: x */
    public static Format m1955x(@Nullable Format format, Format format2, boolean z) {
        if (format == null) {
            return format2;
        }
        int i2 = z ? format.f9241h : -1;
        int i3 = format.f9258y;
        int i4 = i3 != -1 ? i3 : format2.f9258y;
        String m2334l = C2344d0.m2334l(format.f9242i, C2357q.m2543f(format2.f9245l));
        String m2540c = C2357q.m2540c(m2334l);
        if (m2540c == null) {
            m2540c = format2.f9245l;
        }
        String str = m2540c;
        String str2 = format.f9237c;
        String str3 = format.f9238e;
        Metadata metadata = format.f9243j;
        int i5 = format.f9250q;
        int i6 = format.f9251r;
        int i7 = format.f9239f;
        String str4 = format.f9233D;
        Metadata metadata2 = format2.f9243j;
        if (metadata2 != null) {
            metadata = metadata2.m4054e(metadata);
        }
        return new Format(str2, str3, i7, format2.f9240g, i2, m2334l, metadata, format2.f9244k, str, format2.f9246m, format2.f9247n, format2.f9248o, format2.f9249p, i5, i6, format2.f9252s, format2.f9253t, format2.f9254u, format2.f9256w, format2.f9255v, format2.f9257x, i4, format2.f9259z, format2.f9230A, format2.f9231B, format2.f9232C, str4, format2.f9234E, format2.f9235F);
    }

    /* renamed from: z */
    public static int m1956z(int i2) {
        if (i2 == 1) {
            return 2;
        }
        if (i2 != 2) {
            return i2 != 3 ? 0 : 1;
        }
        return 3;
    }

    /* renamed from: A */
    public final boolean m1957A() {
        return this.f4961R != -9223372036854775807L;
    }

    /* renamed from: B */
    public final void m1958B() {
        if (!this.f4952I && this.f4955L == null && this.f4947D) {
            for (c cVar : this.f4987w) {
                if (cVar.m1822r() == null) {
                    return;
                }
            }
            TrackGroupArray trackGroupArray = this.f4953J;
            if (trackGroupArray != null) {
                int i2 = trackGroupArray.f9397e;
                int[] iArr = new int[i2];
                this.f4955L = iArr;
                Arrays.fill(iArr, -1);
                for (int i3 = 0; i3 < i2; i3++) {
                    int i4 = 0;
                    while (true) {
                        c[] cVarArr = this.f4987w;
                        if (i4 < cVarArr.length) {
                            Format m1822r = cVarArr[i4].m1822r();
                            Format format = this.f4953J.f9398f[i3].f9394e[0];
                            String str = m1822r.f9245l;
                            String str2 = format.f9245l;
                            int m2543f = C2357q.m2543f(str);
                            if (m2543f == 3 ? C2344d0.m2323a(str, str2) && (!("application/cea-608".equals(str) || "application/cea-708".equals(str)) || m1822r.f9234E == format.f9234E) : m2543f == C2357q.m2543f(str2)) {
                                this.f4955L[i3] = i4;
                                break;
                            }
                            i4++;
                        }
                    }
                }
                Iterator<C2171n> it = this.f4985u.iterator();
                while (it.hasNext()) {
                    it.next().m1953b();
                }
                return;
            }
            int length = this.f4987w.length;
            int i5 = 0;
            int i6 = 6;
            int i7 = -1;
            while (true) {
                if (i5 >= length) {
                    break;
                }
                String str3 = this.f4987w[i5].m1822r().f9245l;
                int i8 = C2357q.m2547j(str3) ? 2 : C2357q.m2545h(str3) ? 1 : C2357q.m2546i(str3) ? 3 : 6;
                if (m1956z(i8) > m1956z(i6)) {
                    i7 = i5;
                    i6 = i8;
                } else if (i8 == i6 && i7 != -1) {
                    i7 = -1;
                }
                i5++;
            }
            TrackGroup trackGroup = this.f4971g.f4873h;
            int i9 = trackGroup.f9393c;
            this.f4956M = -1;
            this.f4955L = new int[length];
            for (int i10 = 0; i10 < length; i10++) {
                this.f4955L[i10] = i10;
            }
            TrackGroup[] trackGroupArr = new TrackGroup[length];
            for (int i11 = 0; i11 < length; i11++) {
                Format m1822r2 = this.f4987w[i11].m1822r();
                if (i11 == i7) {
                    Format[] formatArr = new Format[i9];
                    if (i9 == 1) {
                        formatArr[0] = m1822r2.m4046q(trackGroup.f9394e[0]);
                    } else {
                        for (int i12 = 0; i12 < i9; i12++) {
                            formatArr[i12] = m1955x(trackGroup.f9394e[i12], m1822r2, true);
                        }
                    }
                    trackGroupArr[i11] = new TrackGroup(formatArr);
                    this.f4956M = i11;
                } else {
                    trackGroupArr[i11] = new TrackGroup(m1955x((i6 == 2 && C2357q.m2545h(m1822r2.f9245l)) ? this.f4973i : null, m1822r2, false));
                }
            }
            this.f4953J = m1965w(trackGroupArr);
            C4195m.m4771I(this.f4954K == null);
            this.f4954K = Collections.emptySet();
            this.f4948E = true;
            ((C2170m) this.f4970f).m1952s();
        }
    }

    /* renamed from: C */
    public void m1959C() {
        this.f4976l.m2184f(Integer.MIN_VALUE);
        C2165h c2165h = this.f4971g;
        IOException iOException = c2165h.f4878m;
        if (iOException != null) {
            throw iOException;
        }
        Uri uri = c2165h.f4879n;
        if (uri == null || !c2165h.f4883r) {
            return;
        }
        ((C2178c) c2165h.f4872g).m1972e(uri);
    }

    /* renamed from: D */
    public void m1960D(TrackGroup[] trackGroupArr, int i2, int... iArr) {
        this.f4953J = m1965w(trackGroupArr);
        this.f4954K = new HashSet();
        for (int i3 : iArr) {
            this.f4954K.add(this.f4953J.f9398f[i3]);
        }
        this.f4956M = i2;
        Handler handler = this.f4984t;
        final a aVar = this.f4970f;
        aVar.getClass();
        handler.post(new Runnable() { // from class: b.l.a.a.k1.m0.c
            @Override // java.lang.Runnable
            public final void run() {
                ((C2170m) C2172o.a.this).m1952s();
            }
        });
        this.f4948E = true;
    }

    /* renamed from: E */
    public final void m1961E() {
        for (c cVar : this.f4987w) {
            cVar.m1805C(this.f4962S);
        }
        this.f4962S = false;
    }

    /* renamed from: F */
    public boolean m1962F(long j2, boolean z) {
        boolean z2;
        this.f4960Q = j2;
        if (m1957A()) {
            this.f4961R = j2;
            return true;
        }
        if (this.f4947D && !z) {
            int length = this.f4987w.length;
            for (int i2 = 0; i2 < length; i2++) {
                if (!this.f4987w[i2].m1807E(j2, false) && (this.f4959P[i2] || !this.f4957N)) {
                    z2 = false;
                    break;
                }
            }
            z2 = true;
            if (z2) {
                return false;
            }
        }
        this.f4961R = j2;
        this.f4964U = false;
        this.f4980p.clear();
        if (this.f4976l.m2183e()) {
            this.f4976l.m2181b();
        } else {
            this.f4976l.f5771e = null;
            m1961E();
        }
        return true;
    }

    /* renamed from: G */
    public void m1963G(long j2) {
        if (this.f4966W != j2) {
            this.f4966W = j2;
            for (c cVar : this.f4987w) {
                if (cVar.f4542C != j2) {
                    cVar.f4542C = j2;
                    cVar.f4540A = true;
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: a */
    public void mo1623a(InterfaceC2050q interfaceC2050q) {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: b */
    public long mo1759b() {
        if (m1957A()) {
            return this.f4961R;
        }
        if (this.f4964U) {
            return Long.MIN_VALUE;
        }
        return m1966y().f4629g;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: c */
    public boolean mo1760c(long j2) {
        List<C2169l> list;
        long max;
        boolean z;
        C2165h.b bVar;
        long j3;
        int i2;
        C2180e c2180e;
        Uri uri;
        byte[] bArr;
        InterfaceC2321m interfaceC2321m;
        int i3;
        C2165h.b bVar2;
        InterfaceC2321m interfaceC2321m2;
        C2324p c2324p;
        boolean z2;
        C2088b c2088b;
        C2360t c2360t;
        InterfaceC2041h interfaceC2041h;
        boolean z3;
        byte[] bArr2;
        String str;
        if (this.f4964U || this.f4976l.m2183e() || this.f4976l.m2182d()) {
            return false;
        }
        if (m1957A()) {
            list = Collections.emptyList();
            max = this.f4961R;
        } else {
            list = this.f4981q;
            C2169l m1966y = m1966y();
            max = m1966y.f4903I ? m1966y.f4629g : Math.max(this.f4960Q, m1966y.f4628f);
        }
        List<C2169l> list2 = list;
        long j4 = max;
        C2165h c2165h = this.f4971g;
        boolean z4 = this.f4948E || !list2.isEmpty();
        C2165h.b bVar3 = this.f4979o;
        Objects.requireNonNull(c2165h);
        C2169l c2169l = list2.isEmpty() ? null : (C2169l) C1499a.m611d(list2, 1);
        int m4059b = c2169l == null ? -1 : c2165h.f4873h.m4059b(c2169l.f4625c);
        long j5 = j4 - j2;
        long j6 = c2165h.f4882q;
        long j7 = (j6 > (-9223372036854775807L) ? 1 : (j6 == (-9223372036854775807L) ? 0 : -1)) != 0 ? j6 - j2 : -9223372036854775807L;
        if (c2169l == null || c2165h.f4880o) {
            z = z4;
            bVar = bVar3;
            j3 = -9223372036854775807L;
        } else {
            z = z4;
            bVar = bVar3;
            long j8 = c2169l.f4629g - c2169l.f4628f;
            j5 = Math.max(0L, j5 - j8);
            j3 = -9223372036854775807L;
            if (j7 != -9223372036854775807L) {
                j7 = Math.max(0L, j7 - j8);
            }
        }
        int i4 = m4059b;
        c2165h.f4881p.mo1942j(j2, j5, j7, list2, c2165h.m1938a(c2169l, j4));
        int mo2155k = c2165h.f4881p.mo2155k();
        boolean z5 = i4 != mo2155k;
        Uri uri2 = c2165h.f4870e[mo2155k];
        if (((C2178c) c2165h.f4872g).m1971d(uri2)) {
            C2165h.b bVar4 = bVar;
            C2180e m1970c = ((C2178c) c2165h.f4872g).m1970c(uri2, true);
            Objects.requireNonNull(m1970c);
            c2165h.f4880o = m1970c.f5085c;
            if (!m1970c.f5067l) {
                j3 = (m1970c.f5061f + m1970c.f5071p) - ((C2178c) c2165h.f4872g).f5027t;
            }
            c2165h.f4882q = j3;
            long j9 = m1970c.f5061f - ((C2178c) c2165h.f4872g).f5027t;
            long m1939b = c2165h.m1939b(c2169l, z5, m1970c, j9, j4);
            if (m1939b >= m1970c.f5064i || c2169l == null || !z5) {
                i2 = mo2155k;
                c2180e = m1970c;
                uri = uri2;
            } else {
                uri = c2165h.f4870e[i4];
                c2180e = ((C2178c) c2165h.f4872g).m1970c(uri, true);
                Objects.requireNonNull(c2180e);
                j9 = c2180e.f5061f - ((C2178c) c2165h.f4872g).f5027t;
                m1939b = c2169l.mo1860c();
                i2 = i4;
            }
            long j10 = c2180e.f5064i;
            if (m1939b < j10) {
                c2165h.f4878m = new C2192o();
            } else {
                int i5 = (int) (m1939b - j10);
                int size = c2180e.f5070o.size();
                if (i5 >= size) {
                    if (!c2180e.f5067l) {
                        bVar4.f4887c = uri;
                        c2165h.f4883r &= uri.equals(c2165h.f4879n);
                        c2165h.f4879n = uri;
                    } else if (z || size == 0) {
                        bVar4.f4886b = true;
                    } else {
                        i5 = size - 1;
                    }
                }
                c2165h.f4883r = false;
                c2165h.f4879n = null;
                C2180e.a aVar = c2180e.f5070o.get(i5);
                C2180e.a aVar2 = aVar.f5073e;
                Uri m2514s1 = (aVar2 == null || (str = aVar2.f5078j) == null) ? null : C2354n.m2514s1(c2180e.f5083a, str);
                AbstractC2122d m1940c = c2165h.m1940c(m2514s1, i2);
                bVar4.f4885a = m1940c;
                if (m1940c == null) {
                    String str2 = aVar.f5078j;
                    Uri m2514s12 = str2 == null ? null : C2354n.m2514s1(c2180e.f5083a, str2);
                    AbstractC2122d m1940c2 = c2165h.m1940c(m2514s12, i2);
                    bVar4.f4885a = m1940c2;
                    if (m1940c2 == null) {
                        InterfaceC2167j interfaceC2167j = c2165h.f4866a;
                        InterfaceC2321m interfaceC2321m3 = c2165h.f4867b;
                        Format format = c2165h.f4871f[i2];
                        List<Format> list3 = c2165h.f4874i;
                        int mo1943m = c2165h.f4881p.mo1943m();
                        Object mo1944o = c2165h.f4881p.mo1944o();
                        boolean z6 = c2165h.f4876k;
                        C2174q c2174q = c2165h.f4869d;
                        C2164g c2164g = c2165h.f4875j;
                        Objects.requireNonNull(c2164g);
                        byte[] bArr3 = m2514s12 == null ? null : c2164g.f4864a.get(m2514s12);
                        C2164g c2164g2 = c2165h.f4875j;
                        Objects.requireNonNull(c2164g2);
                        byte[] bArr4 = m2514s1 == null ? null : c2164g2.f4864a.get(m2514s1);
                        C2049p c2049p = C2169l.f4893j;
                        C2180e.a aVar3 = c2180e.f5070o.get(i5);
                        C2324p c2324p2 = new C2324p(C2354n.m2514s1(c2180e.f5083a, aVar3.f5072c), aVar3.f5080l, aVar3.f5081m, null);
                        boolean z7 = bArr3 != null;
                        if (z7) {
                            String str3 = aVar3.f5079k;
                            Objects.requireNonNull(str3);
                            bArr = C2169l.m1945f(str3);
                        } else {
                            bArr = null;
                        }
                        if (bArr3 != null) {
                            Objects.requireNonNull(bArr);
                            interfaceC2321m = new C2161d(interfaceC2321m3, bArr3, bArr);
                        } else {
                            interfaceC2321m = interfaceC2321m3;
                        }
                        C2180e.a aVar4 = aVar3.f5073e;
                        if (aVar4 != null) {
                            boolean z8 = bArr4 != null;
                            if (z8) {
                                String str4 = aVar4.f5079k;
                                Objects.requireNonNull(str4);
                                bArr2 = C2169l.m1945f(str4);
                            } else {
                                bArr2 = null;
                            }
                            bVar2 = bVar4;
                            i3 = i5;
                            C2324p c2324p3 = new C2324p(C2354n.m2514s1(c2180e.f5083a, aVar4.f5072c), aVar4.f5080l, aVar4.f5081m, null);
                            if (bArr4 != null) {
                                Objects.requireNonNull(bArr2);
                                interfaceC2321m3 = new C2161d(interfaceC2321m3, bArr4, bArr2);
                            }
                            interfaceC2321m2 = interfaceC2321m3;
                            z2 = z8;
                            c2324p = c2324p3;
                        } else {
                            i3 = i5;
                            bVar2 = bVar4;
                            interfaceC2321m2 = null;
                            c2324p = null;
                            z2 = false;
                        }
                        long j11 = j9 + aVar3.f5076h;
                        long j12 = j11 + aVar3.f5074f;
                        int i6 = c2180e.f5063h + aVar3.f5075g;
                        if (c2169l != null) {
                            C2088b c2088b2 = c2169l.f4917y;
                            C2360t c2360t2 = c2169l.f4918z;
                            boolean z9 = (uri.equals(c2169l.f4906n) && c2169l.f4903I) ? false : true;
                            c2088b = c2088b2;
                            c2360t = c2360t2;
                            z3 = z9;
                            interfaceC2041h = (c2169l.f4898D && c2169l.f4905m == i6 && !z9) ? c2169l.f4897C : null;
                        } else {
                            c2088b = new C2088b();
                            c2360t = new C2360t(10);
                            interfaceC2041h = null;
                            z3 = false;
                        }
                        long j13 = c2180e.f5064i + i3;
                        boolean z10 = aVar3.f5082n;
                        C2342c0 c2342c0 = c2174q.f5001a.get(i6);
                        if (c2342c0 == null) {
                            c2342c0 = new C2342c0(Long.MAX_VALUE);
                            c2174q.f5001a.put(i6, c2342c0);
                        }
                        bVar2.f4885a = new C2169l(interfaceC2167j, interfaceC2321m, c2324p2, format, z7, interfaceC2321m2, c2324p, z2, uri, list3, mo1943m, mo1944o, j11, j12, j13, i6, z10, z6, c2342c0, aVar3.f5077i, interfaceC2041h, c2088b, c2360t, z3);
                    }
                }
            }
        } else {
            bVar.f4887c = uri2;
            c2165h.f4883r &= uri2.equals(c2165h.f4879n);
            c2165h.f4879n = uri2;
        }
        C2165h.b bVar5 = this.f4979o;
        boolean z11 = bVar5.f4886b;
        AbstractC2122d abstractC2122d = bVar5.f4885a;
        Uri uri3 = bVar5.f4887c;
        bVar5.f4885a = null;
        bVar5.f4886b = false;
        bVar5.f4887c = null;
        if (z11) {
            this.f4961R = -9223372036854775807L;
            this.f4964U = true;
            return true;
        }
        if (abstractC2122d == null) {
            if (uri3 == null) {
                return false;
            }
            ((C2178c) ((C2170m) this.f4970f).f4920e).f5015h.get(uri3).m1974b();
            return false;
        }
        if (abstractC2122d instanceof C2169l) {
            this.f4961R = -9223372036854775807L;
            C2169l c2169l2 = (C2169l) abstractC2122d;
            c2169l2.f4899E = this;
            int i7 = c2169l2.f4904l;
            boolean z12 = c2169l2.f4913u;
            this.f4968Y = i7;
            for (c cVar : this.f4987w) {
                cVar.f4569z = i7;
            }
            if (z12) {
                for (c cVar2 : this.f4987w) {
                    cVar2.f4543D = true;
                }
            }
            this.f4980p.add(c2169l2);
            this.f4950G = c2169l2.f4625c;
        }
        this.f4977m.m2038n(abstractC2122d.f4623a, abstractC2122d.f4624b, this.f4969e, abstractC2122d.f4625c, abstractC2122d.f4626d, abstractC2122d.f4627e, abstractC2122d.f4628f, abstractC2122d.f4629g, this.f4976l.m2186h(abstractC2122d, this, ((C2331w) this.f4975k).m2280b(abstractC2122d.f4624b)));
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: d */
    public boolean mo1761d() {
        return this.f4976l.m2183e();
    }

    /*  JADX ERROR: NullPointerException in pass: LoopRegionVisitor
        java.lang.NullPointerException: Cannot invoke "jadx.core.dex.instructions.args.SSAVar.use(jadx.core.dex.instructions.args.RegisterArg)" because "ssaVar" is null
        	at jadx.core.dex.nodes.InsnNode.rebindArgs(InsnNode.java:493)
        	at jadx.core.dex.nodes.InsnNode.rebindArgs(InsnNode.java:496)
        */
    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: f */
    public long mo1763f() {
        /*
            r7 = this;
            boolean r0 = r7.f4964U
            if (r0 == 0) goto L7
            r0 = -9223372036854775808
            return r0
        L7:
            boolean r0 = r7.m1957A()
            if (r0 == 0) goto L10
            long r0 = r7.f4961R
            return r0
        L10:
            long r0 = r7.f4960Q
            b.l.a.a.k1.m0.l r2 = r7.m1966y()
            boolean r3 = r2.f4903I
            if (r3 == 0) goto L1b
            goto L34
        L1b:
            java.util.ArrayList<b.l.a.a.k1.m0.l> r2 = r7.f4980p
            int r2 = r2.size()
            r3 = 1
            if (r2 <= r3) goto L33
            java.util.ArrayList<b.l.a.a.k1.m0.l> r2 = r7.f4980p
            int r3 = r2.size()
            int r3 = r3 + (-2)
            java.lang.Object r2 = r2.get(r3)
            b.l.a.a.k1.m0.l r2 = (p005b.p199l.p200a.p201a.p227k1.p232m0.C2169l) r2
            goto L34
        L33:
            r2 = 0
        L34:
            if (r2 == 0) goto L3c
            long r2 = r2.f4629g
            long r0 = java.lang.Math.max(r0, r2)
        L3c:
            boolean r2 = r7.f4947D
            if (r2 == 0) goto L53
            b.l.a.a.k1.m0.o$c[] r2 = r7.f4987w
            int r3 = r2.length
            r4 = 0
        L44:
            if (r4 >= r3) goto L53
            r5 = r2[r4]
            long r5 = r5.m1818n()
            long r0 = java.lang.Math.max(r0, r5)
            int r4 = r4 + 1
            goto L44
        L53:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p232m0.C2172o.mo1763f():long");
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: g */
    public void mo1764g(long j2) {
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.f
    /* renamed from: h */
    public void mo1765h() {
        for (c cVar : this.f4987w) {
            cVar.m1804B();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.C2105d0.b
    /* renamed from: i */
    public void mo1766i(Format format) {
        this.f4984t.post(this.f4982r);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: k */
    public void mo1768k(AbstractC2122d abstractC2122d, long j2, long j3, boolean z) {
        AbstractC2122d abstractC2122d2 = abstractC2122d;
        InterfaceC2203z.a aVar = this.f4977m;
        C2324p c2324p = abstractC2122d2.f4623a;
        C2287d0 c2287d0 = abstractC2122d2.f4630h;
        aVar.m2029e(c2324p, c2287d0.f5798c, c2287d0.f5799d, abstractC2122d2.f4624b, this.f4969e, abstractC2122d2.f4625c, abstractC2122d2.f4626d, abstractC2122d2.f4627e, abstractC2122d2.f4628f, abstractC2122d2.f4629g, j2, j3, c2287d0.f5797b);
        if (z) {
            return;
        }
        m1961E();
        if (this.f4949F > 0) {
            ((C2170m) this.f4970f).mo1421i(this);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: l */
    public void mo1769l(AbstractC2122d abstractC2122d, long j2, long j3) {
        AbstractC2122d abstractC2122d2 = abstractC2122d;
        C2165h c2165h = this.f4971g;
        Objects.requireNonNull(c2165h);
        if (abstractC2122d2 instanceof C2165h.a) {
            C2165h.a aVar = (C2165h.a) abstractC2122d2;
            c2165h.f4877l = aVar.f4683i;
            C2164g c2164g = c2165h.f4875j;
            Uri uri = aVar.f4623a.f5933a;
            byte[] bArr = aVar.f4884k;
            Objects.requireNonNull(bArr);
            LinkedHashMap<Uri, byte[]> linkedHashMap = c2164g.f4864a;
            Objects.requireNonNull(uri);
            linkedHashMap.put(uri, bArr);
        }
        InterfaceC2203z.a aVar2 = this.f4977m;
        C2324p c2324p = abstractC2122d2.f4623a;
        C2287d0 c2287d0 = abstractC2122d2.f4630h;
        aVar2.m2032h(c2324p, c2287d0.f5798c, c2287d0.f5799d, abstractC2122d2.f4624b, this.f4969e, abstractC2122d2.f4625c, abstractC2122d2.f4626d, abstractC2122d2.f4627e, abstractC2122d2.f4628f, abstractC2122d2.f4629g, j2, j3, c2287d0.f5797b);
        if (this.f4948E) {
            ((C2170m) this.f4970f).mo1421i(this);
        } else {
            mo1760c(this.f4960Q);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: o */
    public void mo1624o() {
        this.f4965V = true;
        this.f4984t.post(this.f4983s);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: s */
    public C2281a0.c mo1775s(AbstractC2122d abstractC2122d, long j2, long j3, IOException iOException, int i2) {
        boolean z;
        C2281a0.c m2179c;
        AbstractC2122d abstractC2122d2 = abstractC2122d;
        long j4 = abstractC2122d2.f4630h.f5797b;
        boolean z2 = abstractC2122d2 instanceof C2169l;
        long m2279a = ((C2331w) this.f4975k).m2279a(abstractC2122d2.f4624b, j3, iOException, i2);
        if (m2279a != -9223372036854775807L) {
            C2165h c2165h = this.f4971g;
            InterfaceC2257f interfaceC2257f = c2165h.f4881p;
            z = interfaceC2257f.mo2150c(interfaceC2257f.mo2158q(c2165h.f4873h.m4059b(abstractC2122d2.f4625c)), m2279a);
        } else {
            z = false;
        }
        if (z) {
            if (z2 && j4 == 0) {
                ArrayList<C2169l> arrayList = this.f4980p;
                C4195m.m4771I(arrayList.remove(arrayList.size() + (-1)) == abstractC2122d2);
                if (this.f4980p.isEmpty()) {
                    this.f4961R = this.f4960Q;
                }
            }
            m2179c = C2281a0.f5767a;
        } else {
            long m2281c = ((C2331w) this.f4975k).m2281c(abstractC2122d2.f4624b, j3, iOException, i2);
            m2179c = m2281c != -9223372036854775807L ? C2281a0.m2179c(false, m2281c) : C2281a0.f5768b;
        }
        InterfaceC2203z.a aVar = this.f4977m;
        C2324p c2324p = abstractC2122d2.f4623a;
        C2287d0 c2287d0 = abstractC2122d2.f4630h;
        aVar.m2035k(c2324p, c2287d0.f5798c, c2287d0.f5799d, abstractC2122d2.f4624b, this.f4969e, abstractC2122d2.f4625c, abstractC2122d2.f4626d, abstractC2122d2.f4627e, abstractC2122d2.f4628f, abstractC2122d2.f4629g, j2, j3, j4, iOException, !m2179c.m2187a());
        if (z) {
            if (this.f4948E) {
                ((C2170m) this.f4970f).mo1421i(this);
            } else {
                mo1760c(this.f4960Q);
            }
        }
        return m2179c;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: t */
    public InterfaceC2052s mo1625t(int i2, int i3) {
        InterfaceC2052s interfaceC2052s;
        Set<Integer> set = f4943c;
        if (!set.contains(Integer.valueOf(i3))) {
            int i4 = 0;
            while (true) {
                InterfaceC2052s[] interfaceC2052sArr = this.f4987w;
                if (i4 >= interfaceC2052sArr.length) {
                    break;
                }
                if (this.f4988x[i4] == i2) {
                    interfaceC2052s = interfaceC2052sArr[i4];
                    break;
                }
                i4++;
            }
        } else {
            C4195m.m4765F(set.contains(Integer.valueOf(i3)));
            int i5 = this.f4990z.get(i3, -1);
            if (i5 != -1) {
                if (this.f4989y.add(Integer.valueOf(i3))) {
                    this.f4988x[i5] = i2;
                }
                interfaceC2052s = this.f4988x[i5] == i2 ? this.f4987w[i5] : new C2036g();
            }
            interfaceC2052s = null;
        }
        if (interfaceC2052s == null) {
            if (this.f4965V) {
                return new C2036g();
            }
            int length = this.f4987w.length;
            boolean z = i3 == 1 || i3 == 2;
            c cVar = new c(this.f4972h, this.f4974j, this.f4986v);
            if (z) {
                cVar.f5000F = this.f4967X;
                cVar.f4540A = true;
            }
            cVar.m1808F(this.f4966W);
            cVar.f4569z = this.f4968Y;
            cVar.f4547d = this;
            int i6 = length + 1;
            int[] copyOf = Arrays.copyOf(this.f4988x, i6);
            this.f4988x = copyOf;
            copyOf[length] = i2;
            c[] cVarArr = this.f4987w;
            int i7 = C2344d0.f6035a;
            Object[] copyOf2 = Arrays.copyOf(cVarArr, cVarArr.length + 1);
            copyOf2[cVarArr.length] = cVar;
            this.f4987w = (c[]) copyOf2;
            boolean[] copyOf3 = Arrays.copyOf(this.f4959P, i6);
            this.f4959P = copyOf3;
            copyOf3[length] = z;
            this.f4957N = copyOf3[length] | this.f4957N;
            this.f4989y.add(Integer.valueOf(i3));
            this.f4990z.append(i3, length);
            if (m1956z(i3) > m1956z(this.f4945B)) {
                this.f4946C = length;
                this.f4945B = i3;
            }
            this.f4958O = Arrays.copyOf(this.f4958O, i6);
            interfaceC2052s = cVar;
        }
        if (i3 != 4) {
            return interfaceC2052s;
        }
        if (this.f4944A == null) {
            this.f4944A = new b(interfaceC2052s, this.f4978n);
        }
        return this.f4944A;
    }

    @EnsuresNonNull({"trackGroups", "optionalTrackGroups"})
    /* renamed from: v */
    public final void m1964v() {
        C4195m.m4771I(this.f4948E);
        Objects.requireNonNull(this.f4953J);
        Objects.requireNonNull(this.f4954K);
    }

    /* renamed from: w */
    public final TrackGroupArray m1965w(TrackGroup[] trackGroupArr) {
        for (int i2 = 0; i2 < trackGroupArr.length; i2++) {
            TrackGroup trackGroup = trackGroupArr[i2];
            Format[] formatArr = new Format[trackGroup.f9393c];
            for (int i3 = 0; i3 < trackGroup.f9393c; i3++) {
                Format format = trackGroup.f9394e[i3];
                DrmInitData drmInitData = format.f9248o;
                if (drmInitData != null) {
                    format = format.m4043e(this.f4974j.mo1442a(drmInitData));
                }
                formatArr[i3] = format;
            }
            trackGroupArr[i2] = new TrackGroup(formatArr);
        }
        return new TrackGroupArray(trackGroupArr);
    }

    /* renamed from: y */
    public final C2169l m1966y() {
        return this.f4980p.get(r0.size() - 1);
    }
}
