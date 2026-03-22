package p005b.p199l.p200a.p201a.p227k1.p230l0;

import android.util.Pair;
import android.util.SparseIntArray;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p227k1.C2195r;
import p005b.p199l.p200a.p201a.p227k1.C2196s;
import p005b.p199l.p200a.p201a.p227k1.C2197t;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2125g;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2143j;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2143j.c;
import p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2136c;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2152i;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2144a;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2145b;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2147d;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2148e;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2149f;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2283b0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.l0.e */
/* loaded from: classes.dex */
public final class C2138e implements InterfaceC2201x, InterfaceC2109f0.a<C2125g<InterfaceC2136c>>, C2125g.b<InterfaceC2136c> {

    /* renamed from: c */
    public static final Pattern f4699c = Pattern.compile("CC([1-4])=(.+)");

    /* renamed from: e */
    public final int f4700e;

    /* renamed from: f */
    public final InterfaceC2136c.a f4701f;

    /* renamed from: g */
    @Nullable
    public final InterfaceC2291f0 f4702g;

    /* renamed from: h */
    public final InterfaceC1954e<?> f4703h;

    /* renamed from: i */
    public final InterfaceC2334z f4704i;

    /* renamed from: j */
    public final long f4705j;

    /* renamed from: k */
    public final InterfaceC2283b0 f4706k;

    /* renamed from: l */
    public final InterfaceC2288e f4707l;

    /* renamed from: m */
    public final TrackGroupArray f4708m;

    /* renamed from: n */
    public final a[] f4709n;

    /* renamed from: o */
    public final C2196s f4710o;

    /* renamed from: p */
    public final C2143j f4711p;

    /* renamed from: r */
    public final InterfaceC2203z.a f4713r;

    /* renamed from: s */
    @Nullable
    public InterfaceC2201x.a f4714s;

    /* renamed from: v */
    public InterfaceC2109f0 f4717v;

    /* renamed from: w */
    public C2145b f4718w;

    /* renamed from: x */
    public int f4719x;

    /* renamed from: y */
    public List<C2148e> f4720y;

    /* renamed from: z */
    public boolean f4721z;

    /* renamed from: t */
    public C2125g<InterfaceC2136c>[] f4715t = new C2125g[0];

    /* renamed from: u */
    public C2142i[] f4716u = new C2142i[0];

    /* renamed from: q */
    public final IdentityHashMap<C2125g<InterfaceC2136c>, C2143j.c> f4712q = new IdentityHashMap<>();

    /* renamed from: b.l.a.a.k1.l0.e$a */
    public static final class a {

        /* renamed from: a */
        public final int[] f4722a;

        /* renamed from: b */
        public final int f4723b;

        /* renamed from: c */
        public final int f4724c;

        /* renamed from: d */
        public final int f4725d;

        /* renamed from: e */
        public final int f4726e;

        /* renamed from: f */
        public final int f4727f;

        /* renamed from: g */
        public final int f4728g;

        public a(int i2, int i3, int[] iArr, int i4, int i5, int i6, int i7) {
            this.f4723b = i2;
            this.f4722a = iArr;
            this.f4724c = i3;
            this.f4726e = i4;
            this.f4727f = i5;
            this.f4728g = i6;
            this.f4725d = i7;
        }
    }

    public C2138e(int i2, C2145b c2145b, int i3, InterfaceC2136c.a aVar, @Nullable InterfaceC2291f0 interfaceC2291f0, InterfaceC1954e<?> interfaceC1954e, InterfaceC2334z interfaceC2334z, InterfaceC2203z.a aVar2, long j2, InterfaceC2283b0 interfaceC2283b0, InterfaceC2288e interfaceC2288e, C2196s c2196s, C2143j.b bVar) {
        int i4;
        List<C2144a> list;
        int i5;
        boolean z;
        Format[] formatArr;
        C2147d c2147d;
        int i6;
        this.f4700e = i2;
        this.f4718w = c2145b;
        this.f4719x = i3;
        this.f4701f = aVar;
        this.f4702g = interfaceC2291f0;
        this.f4703h = interfaceC1954e;
        this.f4704i = interfaceC2334z;
        this.f4713r = aVar2;
        this.f4705j = j2;
        this.f4706k = interfaceC2283b0;
        this.f4707l = interfaceC2288e;
        this.f4710o = c2196s;
        this.f4711p = new C2143j(c2145b, bVar, interfaceC2288e);
        C2125g<InterfaceC2136c>[] c2125gArr = this.f4715t;
        Objects.requireNonNull(c2196s);
        this.f4717v = new C2195r(c2125gArr);
        C2149f c2149f = c2145b.f4791l.get(i3);
        List<C2148e> list2 = c2149f.f4813d;
        this.f4720y = list2;
        List<C2144a> list3 = c2149f.f4812c;
        int size = list3.size();
        SparseIntArray sparseIntArray = new SparseIntArray(size);
        for (int i7 = 0; i7 < size; i7++) {
            sparseIntArray.put(list3.get(i7).f4775a, i7);
        }
        int[][] iArr = new int[size][];
        boolean[] zArr = new boolean[size];
        int i8 = 0;
        for (int i9 = 0; i9 < size; i9++) {
            if (!zArr[i9]) {
                zArr[i9] = true;
                List<C2147d> list4 = list3.get(i9).f4779e;
                int i10 = 0;
                while (true) {
                    if (i10 >= list4.size()) {
                        c2147d = null;
                        break;
                    }
                    c2147d = list4.get(i10);
                    if ("urn:mpeg:dash:adaptation-set-switching:2016".equals(c2147d.f4803a)) {
                        break;
                    } else {
                        i10++;
                    }
                }
                if (c2147d == null) {
                    i6 = i8 + 1;
                    iArr[i8] = new int[]{i9};
                } else {
                    String[] m2316H = C2344d0.m2316H(c2147d.f4804b, ChineseToPinyinResource.Field.COMMA);
                    int length = m2316H.length + 1;
                    int[] iArr2 = new int[length];
                    iArr2[0] = i9;
                    int length2 = m2316H.length;
                    int i11 = 0;
                    int i12 = 1;
                    while (i11 < length2) {
                        int i13 = length2;
                        String[] strArr = m2316H;
                        int i14 = sparseIntArray.get(Integer.parseInt(m2316H[i11]), -1);
                        if (i14 != -1) {
                            zArr[i14] = true;
                            iArr2[i12] = i14;
                            i12++;
                        }
                        i11++;
                        length2 = i13;
                        m2316H = strArr;
                    }
                    i6 = i8 + 1;
                    iArr[i8] = i12 < length ? Arrays.copyOf(iArr2, i12) : iArr2;
                }
                i8 = i6;
            }
        }
        iArr = i8 < size ? (int[][]) Arrays.copyOf(iArr, i8) : iArr;
        int length3 = iArr.length;
        boolean[] zArr2 = new boolean[length3];
        Format[][] formatArr2 = new Format[length3][];
        int i15 = 0;
        for (int i16 = 0; i16 < length3; i16++) {
            int[] iArr3 = iArr[i16];
            int length4 = iArr3.length;
            int i17 = 0;
            while (true) {
                if (i17 >= length4) {
                    z = false;
                    break;
                }
                List<AbstractC2152i> list5 = list3.get(iArr3[i17]).f4777c;
                for (int i18 = 0; i18 < list5.size(); i18++) {
                    if (!list5.get(i18).f4826d.isEmpty()) {
                        z = true;
                        break;
                    }
                }
                i17++;
            }
            if (z) {
                zArr2[i16] = true;
                i15++;
            }
            int[] iArr4 = iArr[i16];
            int length5 = iArr4.length;
            int i19 = 0;
            while (true) {
                if (i19 >= length5) {
                    formatArr = new Format[0];
                    break;
                }
                int i20 = iArr4[i19];
                C2144a c2144a = list3.get(i20);
                List<C2147d> list6 = list3.get(i20).f4778d;
                int i21 = 0;
                int[] iArr5 = iArr4;
                while (i21 < list6.size()) {
                    C2147d c2147d2 = list6.get(i21);
                    int i22 = length5;
                    List<C2147d> list7 = list6;
                    if ("urn:scte:dash:cc:cea-608:2015".equals(c2147d2.f4803a)) {
                        String str = c2147d2.f4804b;
                        if (str != null) {
                            int i23 = C2344d0.f6035a;
                            String[] split = str.split(";", -1);
                            Format[] formatArr3 = new Format[split.length];
                            int i24 = 0;
                            while (true) {
                                if (i24 >= split.length) {
                                    formatArr = formatArr3;
                                    break;
                                }
                                Matcher matcher = f4699c.matcher(split[i24]);
                                if (!matcher.matches()) {
                                    formatArr = new Format[]{m1865a(c2144a.f4775a, null, -1)};
                                    break;
                                }
                                formatArr3[i24] = m1865a(c2144a.f4775a, matcher.group(2), Integer.parseInt(matcher.group(1)));
                                i24++;
                                split = split;
                                c2144a = c2144a;
                            }
                        } else {
                            formatArr = new Format[]{m1865a(c2144a.f4775a, null, -1)};
                        }
                    } else {
                        i21++;
                        list6 = list7;
                        length5 = i22;
                    }
                }
                i19++;
                iArr4 = iArr5;
            }
            formatArr2[i16] = formatArr;
            if (formatArr2[i16].length != 0) {
                i15++;
            }
        }
        int size2 = list2.size() + i15 + length3;
        TrackGroup[] trackGroupArr = new TrackGroup[size2];
        a[] aVarArr = new a[size2];
        int i25 = 0;
        int i26 = 0;
        while (i26 < length3) {
            int[] iArr6 = iArr[i26];
            ArrayList arrayList = new ArrayList();
            int length6 = iArr6.length;
            int i27 = length3;
            int i28 = 0;
            while (i28 < length6) {
                arrayList.addAll(list3.get(iArr6[i28]).f4777c);
                i28++;
                iArr = iArr;
            }
            int[][] iArr7 = iArr;
            int size3 = arrayList.size();
            Format[] formatArr4 = new Format[size3];
            int i29 = 0;
            while (i29 < size3) {
                int i30 = size3;
                Format format = ((AbstractC2152i) arrayList.get(i29)).f4823a;
                ArrayList arrayList2 = arrayList;
                DrmInitData drmInitData = format.f9248o;
                if (drmInitData != null) {
                    format = format.m4043e(interfaceC1954e.mo1442a(drmInitData));
                }
                formatArr4[i29] = format;
                i29++;
                size3 = i30;
                arrayList = arrayList2;
            }
            C2144a c2144a2 = list3.get(iArr6[0]);
            int i31 = i25 + 1;
            if (zArr2[i26]) {
                list = list3;
                i4 = i31;
                i31++;
            } else {
                i4 = -1;
                list = list3;
            }
            if (formatArr2[i26].length != 0) {
                i5 = i31 + 1;
            } else {
                i5 = i31;
                i31 = -1;
            }
            trackGroupArr[i25] = new TrackGroup(formatArr4);
            int i32 = i31;
            int i33 = i4;
            aVarArr[i25] = new a(c2144a2.f4776b, 0, iArr6, i25, i33, i32, -1);
            if (i33 != -1) {
                trackGroupArr[i33] = new TrackGroup(Format.m4028E(C1499a.m580B(new StringBuilder(), c2144a2.f4775a, ":emsg"), "application/x-emsg", null, -1, null));
                aVarArr[i33] = new a(4, 1, iArr6, i25, -1, -1, -1);
            }
            if (i32 != -1) {
                trackGroupArr[i32] = new TrackGroup(formatArr2[i26]);
                aVarArr[i32] = new a(3, 1, iArr6, i25, -1, -1, -1);
            }
            i26++;
            length3 = i27;
            iArr = iArr7;
            list3 = list;
            i25 = i5;
        }
        int i34 = 0;
        while (i34 < list2.size()) {
            trackGroupArr[i25] = new TrackGroup(Format.m4028E(list2.get(i34).m1914a(), "application/x-emsg", null, -1, null));
            aVarArr[i25] = new a(4, 2, new int[0], -1, -1, -1, i34);
            i34++;
            i25++;
        }
        Pair create = Pair.create(new TrackGroupArray(trackGroupArr), aVarArr);
        this.f4708m = (TrackGroupArray) create.first;
        this.f4709n = (a[]) create.second;
        aVar2.m2040p();
    }

    /* renamed from: a */
    public static Format m1865a(int i2, String str, int i3) {
        StringBuilder sb = new StringBuilder();
        sb.append(i2);
        sb.append(":cea608");
        sb.append(i3 != -1 ? C1499a.m626l(":", i3) : "");
        return Format.m4032I(sb.toString(), "application/cea-608", null, -1, 0, str, i3, null, Long.MAX_VALUE, null);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: b */
    public long mo1759b() {
        return this.f4717v.mo1759b();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: c */
    public boolean mo1760c(long j2) {
        return this.f4717v.mo1760c(j2);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: d */
    public boolean mo1761d() {
        return this.f4717v.mo1761d();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: e */
    public long mo1762e(long j2, C2400v0 c2400v0) {
        for (C2125g<InterfaceC2136c> c2125g : this.f4715t) {
            if (c2125g.f4649c == 2) {
                return c2125g.f4653h.mo1856e(j2, c2400v0);
            }
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: f */
    public long mo1763f() {
        return this.f4717v.mo1763f();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: g */
    public void mo1764g(long j2) {
        this.f4717v.mo1764g(j2);
    }

    /* renamed from: h */
    public final int m1866h(int i2, int[] iArr) {
        int i3 = iArr[i2];
        if (i3 == -1) {
            return -1;
        }
        int i4 = this.f4709n[i3].f4726e;
        for (int i5 = 0; i5 < iArr.length; i5++) {
            int i6 = iArr[i5];
            if (i6 == i4 && this.f4709n[i6].f4724c == 0) {
                return i5;
            }
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0.a
    /* renamed from: i */
    public void mo1421i(C2125g<InterfaceC2136c> c2125g) {
        this.f4714s.mo1421i(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: j */
    public long mo1767j(InterfaceC2257f[] interfaceC2257fArr, boolean[] zArr, InterfaceC2107e0[] interfaceC2107e0Arr, boolean[] zArr2, long j2) {
        int i2;
        boolean z;
        int[] iArr;
        int i3;
        int[] iArr2;
        TrackGroup trackGroup;
        int i4;
        TrackGroup trackGroup2;
        int i5;
        C2143j.c cVar;
        InterfaceC2257f[] interfaceC2257fArr2 = interfaceC2257fArr;
        int[] iArr3 = new int[interfaceC2257fArr2.length];
        int i6 = 0;
        while (true) {
            i2 = -1;
            if (i6 >= interfaceC2257fArr2.length) {
                break;
            }
            if (interfaceC2257fArr2[i6] != null) {
                iArr3[i6] = this.f4708m.m4060b(interfaceC2257fArr2[i6].mo2149a());
            } else {
                iArr3[i6] = -1;
            }
            i6++;
        }
        for (int i7 = 0; i7 < interfaceC2257fArr2.length; i7++) {
            if (interfaceC2257fArr2[i7] == null || !zArr[i7]) {
                if (interfaceC2107e0Arr[i7] instanceof C2125g) {
                    ((C2125g) interfaceC2107e0Arr[i7]).m1843A(this);
                } else if (interfaceC2107e0Arr[i7] instanceof C2125g.a) {
                    ((C2125g.a) interfaceC2107e0Arr[i7]).m1853c();
                }
                interfaceC2107e0Arr[i7] = null;
            }
        }
        int i8 = 0;
        while (true) {
            z = true;
            boolean z2 = true;
            if (i8 >= interfaceC2257fArr2.length) {
                break;
            }
            if ((interfaceC2107e0Arr[i8] instanceof C2197t) || (interfaceC2107e0Arr[i8] instanceof C2125g.a)) {
                int m1866h = m1866h(i8, iArr3);
                if (m1866h == -1) {
                    z2 = interfaceC2107e0Arr[i8] instanceof C2197t;
                } else if (!(interfaceC2107e0Arr[i8] instanceof C2125g.a) || ((C2125g.a) interfaceC2107e0Arr[i8]).f4671c != interfaceC2107e0Arr[m1866h]) {
                    z2 = false;
                }
                if (!z2) {
                    if (interfaceC2107e0Arr[i8] instanceof C2125g.a) {
                        ((C2125g.a) interfaceC2107e0Arr[i8]).m1853c();
                    }
                    interfaceC2107e0Arr[i8] = null;
                }
            }
            i8++;
        }
        InterfaceC2107e0[] interfaceC2107e0Arr2 = interfaceC2107e0Arr;
        int i9 = 0;
        while (i9 < interfaceC2257fArr2.length) {
            InterfaceC2257f interfaceC2257f = interfaceC2257fArr2[i9];
            if (interfaceC2257f == null) {
                i3 = i9;
                iArr2 = iArr3;
            } else if (interfaceC2107e0Arr2[i9] == null) {
                zArr2[i9] = z;
                a aVar = this.f4709n[iArr3[i9]];
                int i10 = aVar.f4724c;
                if (i10 == 0) {
                    int i11 = aVar.f4727f;
                    boolean z3 = i11 != i2;
                    if (z3) {
                        trackGroup = this.f4708m.f9398f[i11];
                        i4 = 1;
                    } else {
                        trackGroup = null;
                        i4 = 0;
                    }
                    int i12 = aVar.f4728g;
                    boolean z4 = i12 != i2;
                    if (z4) {
                        trackGroup2 = this.f4708m.f9398f[i12];
                        i4 += trackGroup2.f9393c;
                    } else {
                        trackGroup2 = null;
                    }
                    Format[] formatArr = new Format[i4];
                    int[] iArr4 = new int[i4];
                    if (z3) {
                        formatArr[0] = trackGroup.f9394e[0];
                        iArr4[0] = 4;
                        i5 = 1;
                    } else {
                        i5 = 0;
                    }
                    ArrayList arrayList = new ArrayList();
                    if (z4) {
                        for (int i13 = 0; i13 < trackGroup2.f9393c; i13++) {
                            formatArr[i5] = trackGroup2.f9394e[i13];
                            iArr4[i5] = 3;
                            arrayList.add(formatArr[i5]);
                            i5 += z ? 1 : 0;
                        }
                    }
                    if (this.f4718w.f4783d && z3) {
                        C2143j c2143j = this.f4711p;
                        cVar = c2143j.new c(c2143j.f4758c);
                    } else {
                        cVar = null;
                    }
                    i3 = i9;
                    C2143j.c cVar2 = cVar;
                    iArr2 = iArr3;
                    C2125g<InterfaceC2136c> c2125g = new C2125g<>(aVar.f4723b, iArr4, formatArr, this.f4701f.mo1864a(this.f4706k, this.f4718w, this.f4719x, aVar.f4722a, interfaceC2257f, aVar.f4723b, this.f4705j, z3, arrayList, cVar, this.f4702g), this, this.f4707l, j2, this.f4703h, this.f4704i, this.f4713r);
                    synchronized (this) {
                        this.f4712q.put(c2125g, cVar2);
                    }
                    interfaceC2107e0Arr[i3] = c2125g;
                    interfaceC2107e0Arr2 = interfaceC2107e0Arr;
                } else {
                    i3 = i9;
                    iArr2 = iArr3;
                    if (i10 == 2) {
                        interfaceC2107e0Arr2[i3] = new C2142i(this.f4720y.get(aVar.f4725d), interfaceC2257f.mo2149a().f9394e[0], this.f4718w.f4783d);
                    }
                }
            } else {
                i3 = i9;
                iArr2 = iArr3;
                if (interfaceC2107e0Arr2[i3] instanceof C2125g) {
                    ((InterfaceC2136c) ((C2125g) interfaceC2107e0Arr2[i3]).f4653h).mo1862b(interfaceC2257f);
                }
            }
            i9 = i3 + 1;
            interfaceC2257fArr2 = interfaceC2257fArr;
            iArr3 = iArr2;
            z = true;
            i2 = -1;
        }
        int[] iArr5 = iArr3;
        int i14 = 0;
        while (i14 < interfaceC2257fArr.length) {
            if (interfaceC2107e0Arr2[i14] != null || interfaceC2257fArr[i14] == null) {
                iArr = iArr5;
            } else {
                iArr = iArr5;
                a aVar2 = this.f4709n[iArr[i14]];
                if (aVar2.f4724c == 1) {
                    int m1866h2 = m1866h(i14, iArr);
                    if (m1866h2 != -1) {
                        C2125g c2125g2 = (C2125g) interfaceC2107e0Arr2[m1866h2];
                        int i15 = aVar2.f4723b;
                        for (int i16 = 0; i16 < c2125g2.f4662q.length; i16++) {
                            if (c2125g2.f4650e[i16] == i15) {
                                C4195m.m4771I(!c2125g2.f4652g[i16]);
                                c2125g2.f4652g[i16] = true;
                                c2125g2.f4662q[i16].m1807E(j2, true);
                                interfaceC2107e0Arr2[i14] = new C2125g.a(c2125g2, c2125g2.f4662q[i16], i16);
                            }
                        }
                        throw new IllegalStateException();
                    }
                    interfaceC2107e0Arr2[i14] = new C2197t();
                    i14++;
                    iArr5 = iArr;
                }
            }
            i14++;
            iArr5 = iArr;
        }
        ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList();
        for (InterfaceC2107e0 interfaceC2107e0 : interfaceC2107e0Arr2) {
            if (interfaceC2107e0 instanceof C2125g) {
                arrayList2.add((C2125g) interfaceC2107e0);
            } else if (interfaceC2107e0 instanceof C2142i) {
                arrayList3.add((C2142i) interfaceC2107e0);
            }
        }
        C2125g<InterfaceC2136c>[] c2125gArr = new C2125g[arrayList2.size()];
        this.f4715t = c2125gArr;
        arrayList2.toArray(c2125gArr);
        C2142i[] c2142iArr = new C2142i[arrayList3.size()];
        this.f4716u = c2142iArr;
        arrayList3.toArray(c2142iArr);
        C2196s c2196s = this.f4710o;
        C2125g<InterfaceC2136c>[] c2125gArr2 = this.f4715t;
        Objects.requireNonNull(c2196s);
        this.f4717v = new C2195r(c2125gArr2);
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: m */
    public void mo1770m() {
        this.f4706k.mo2180a();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: n */
    public long mo1771n(long j2) {
        for (C2125g<InterfaceC2136c> c2125g : this.f4715t) {
            c2125g.m1844B(j2);
        }
        for (C2142i c2142i : this.f4716u) {
            c2142i.m1884b(j2);
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: p */
    public long mo1772p() {
        if (this.f4721z) {
            return -9223372036854775807L;
        }
        this.f4713r.m2043s();
        this.f4721z = true;
        return -9223372036854775807L;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: q */
    public void mo1773q(InterfaceC2201x.a aVar, long j2) {
        this.f4714s = aVar;
        aVar.mo1423k(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: r */
    public TrackGroupArray mo1774r() {
        return this.f4708m;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: u */
    public void mo1776u(long j2, boolean z) {
        for (C2125g<InterfaceC2136c> c2125g : this.f4715t) {
            c2125g.m1846u(j2, z);
        }
    }
}
