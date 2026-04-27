package Q1;

import android.content.Context;
import com.facebook.react.uimanager.W;
import h2.C0562h;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private W f2417a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private W f2418b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private W f2419c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private W f2420d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private W f2421e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private W f2422f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private W f2423g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private W f2424h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private W f2425i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private W f2426j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private W f2427k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private W f2428l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private W f2429m;

    public /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f2430a;

        static {
            int[] iArr = new int[d.values().length];
            try {
                iArr[d.f2402b.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[d.f2403c.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[d.f2404d.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[d.f2406f.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                iArr[d.f2405e.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                iArr[d.f2407g.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                iArr[d.f2408h.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                iArr[d.f2409i.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                iArr[d.f2410j.ordinal()] = 9;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                iArr[d.f2414n.ordinal()] = 10;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                iArr[d.f2413m.ordinal()] = 11;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                iArr[d.f2412l.ordinal()] = 12;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                iArr[d.f2411k.ordinal()] = 13;
            } catch (NoSuchFieldError unused13) {
            }
            f2430a = iArr;
        }
    }

    public e() {
        this(null, null, null, null, null, null, null, null, null, null, null, null, null, 8191, null);
    }

    private final j a(k kVar, k kVar2, k kVar3, k kVar4, float f3, float f4) {
        float fB = kVar.b() + kVar3.b();
        float fA = kVar.a() + kVar2.a();
        float fB2 = kVar2.b() + kVar4.b();
        float fA2 = kVar3.a() + kVar4.a();
        float fMin = fB > 0.0f ? Math.min(f4 / fB, 1.0f) : 0.0f;
        float fMin2 = fA > 0.0f ? Math.min(f3 / fA, 1.0f) : 0.0f;
        float fMin3 = fB2 > 0.0f ? Math.min(f4 / fB2, 1.0f) : 0.0f;
        float fMin4 = fA2 > 0.0f ? Math.min(f3 / fA2, 1.0f) : 0.0f;
        return new j(new k(kVar.a() * Math.min(fMin2, fMin), kVar.b() * Math.min(fMin2, fMin)), new k(kVar2.a() * Math.min(fMin3, fMin2), kVar2.b() * Math.min(fMin3, fMin2)), new k(kVar3.a() * Math.min(fMin4, fMin), kVar3.b() * Math.min(fMin4, fMin)), new k(kVar4.a() * Math.min(fMin4, fMin3), kVar4.b() * Math.min(fMin4, fMin3)));
    }

    public final W b(d dVar) {
        t2.j.f(dVar, "property");
        switch (a.f2430a[dVar.ordinal()]) {
            case 1:
                return this.f2417a;
            case 2:
                return this.f2418b;
            case 3:
                return this.f2419c;
            case 4:
                return this.f2420d;
            case 5:
                return this.f2421e;
            case 6:
                return this.f2422f;
            case 7:
                return this.f2423g;
            case 8:
                return this.f2424h;
            case 9:
                return this.f2425i;
            case 10:
                return this.f2426j;
            case 11:
                return this.f2427k;
            case 12:
                return this.f2428l;
            case 13:
                return this.f2429m;
            default:
                throw new C0562h();
        }
    }

    public final boolean c() {
        return (this.f2417a == null && this.f2418b == null && this.f2419c == null && this.f2420d == null && this.f2421e == null && this.f2422f == null && this.f2423g == null && this.f2424h == null && this.f2425i == null && this.f2426j == null && this.f2427k == null && this.f2428l == null && this.f2429m == null) ? false : true;
    }

    public final j d(int i3, Context context, float f3, float f4) {
        k kVarC;
        k kVarC2;
        k kVarC3;
        k kVarC4;
        k kVarC5;
        k kVarC6;
        k kVarC7;
        k kVarC8;
        k kVarC9;
        k kVarC10;
        k kVarC11;
        k kVarC12;
        t2.j.f(context, "context");
        k kVar = new k(0.0f, 0.0f);
        if (i3 == 0) {
            W w3 = this.f2426j;
            if (w3 == null && (w3 = this.f2422f) == null && (w3 = this.f2418b) == null) {
                w3 = this.f2417a;
            }
            k kVar2 = (w3 == null || (kVarC4 = w3.c(f3, f4)) == null) ? kVar : kVarC4;
            W w4 = this.f2428l;
            if (w4 == null && (w4 = this.f2423g) == null && (w4 = this.f2419c) == null) {
                w4 = this.f2417a;
            }
            k kVar3 = (w4 == null || (kVarC3 = w4.c(f3, f4)) == null) ? kVar : kVarC3;
            W w5 = this.f2427k;
            if (w5 == null && (w5 = this.f2424h) == null && (w5 = this.f2420d) == null) {
                w5 = this.f2417a;
            }
            k kVar4 = (w5 == null || (kVarC2 = w5.c(f3, f4)) == null) ? kVar : kVarC2;
            W w6 = this.f2429m;
            if (w6 == null && (w6 = this.f2425i) == null && (w6 = this.f2421e) == null) {
                w6 = this.f2417a;
            }
            return a(kVar2, kVar3, kVar4, (w6 == null || (kVarC = w6.c(f3, f4)) == null) ? kVar : kVarC, f3, f4);
        }
        if (i3 != 1) {
            throw new IllegalArgumentException("Expected?.resolved layout direction");
        }
        if (com.facebook.react.modules.i18nmanager.a.f7103a.a().d(context)) {
            W w7 = this.f2428l;
            if (w7 == null && (w7 = this.f2423g) == null && (w7 = this.f2419c) == null) {
                w7 = this.f2417a;
            }
            k kVar5 = (w7 == null || (kVarC12 = w7.c(f3, f4)) == null) ? kVar : kVarC12;
            W w8 = this.f2426j;
            if (w8 == null && (w8 = this.f2422f) == null && (w8 = this.f2418b) == null) {
                w8 = this.f2417a;
            }
            k kVar6 = (w8 == null || (kVarC11 = w8.c(f3, f4)) == null) ? kVar : kVarC11;
            W w9 = this.f2429m;
            if (w9 == null && (w9 = this.f2425i) == null && (w9 = this.f2421e) == null) {
                w9 = this.f2417a;
            }
            k kVar7 = (w9 == null || (kVarC10 = w9.c(f3, f4)) == null) ? kVar : kVarC10;
            W w10 = this.f2427k;
            if (w10 == null && (w10 = this.f2424h) == null && (w10 = this.f2420d) == null) {
                w10 = this.f2417a;
            }
            return a(kVar5, kVar6, kVar7, (w10 == null || (kVarC9 = w10.c(f3, f4)) == null) ? kVar : kVarC9, f3, f4);
        }
        W w11 = this.f2428l;
        if (w11 == null && (w11 = this.f2423g) == null && (w11 = this.f2418b) == null) {
            w11 = this.f2417a;
        }
        k kVar8 = (w11 == null || (kVarC8 = w11.c(f3, f4)) == null) ? kVar : kVarC8;
        W w12 = this.f2426j;
        if (w12 == null && (w12 = this.f2422f) == null && (w12 = this.f2419c) == null) {
            w12 = this.f2417a;
        }
        k kVar9 = (w12 == null || (kVarC7 = w12.c(f3, f4)) == null) ? kVar : kVarC7;
        W w13 = this.f2429m;
        if (w13 == null && (w13 = this.f2424h) == null && (w13 = this.f2420d) == null) {
            w13 = this.f2417a;
        }
        k kVar10 = (w13 == null || (kVarC6 = w13.c(f3, f4)) == null) ? kVar : kVarC6;
        W w14 = this.f2427k;
        if (w14 == null && (w14 = this.f2425i) == null && (w14 = this.f2421e) == null) {
            w14 = this.f2417a;
        }
        return a(kVar8, kVar9, kVar10, (w14 == null || (kVarC5 = w14.c(f3, f4)) == null) ? kVar : kVarC5, f3, f4);
    }

    public final void e(d dVar, W w3) {
        t2.j.f(dVar, "property");
        switch (a.f2430a[dVar.ordinal()]) {
            case 1:
                this.f2417a = w3;
                return;
            case 2:
                this.f2418b = w3;
                return;
            case 3:
                this.f2419c = w3;
                return;
            case 4:
                this.f2420d = w3;
                return;
            case 5:
                this.f2421e = w3;
                return;
            case 6:
                this.f2422f = w3;
                return;
            case 7:
                this.f2423g = w3;
                return;
            case 8:
                this.f2424h = w3;
                return;
            case 9:
                this.f2425i = w3;
                return;
            case 10:
                this.f2426j = w3;
                return;
            case 11:
                this.f2427k = w3;
                return;
            case 12:
                this.f2428l = w3;
                return;
            case 13:
                this.f2429m = w3;
                return;
            default:
                throw new C0562h();
        }
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return t2.j.b(this.f2417a, eVar.f2417a) && t2.j.b(this.f2418b, eVar.f2418b) && t2.j.b(this.f2419c, eVar.f2419c) && t2.j.b(this.f2420d, eVar.f2420d) && t2.j.b(this.f2421e, eVar.f2421e) && t2.j.b(this.f2422f, eVar.f2422f) && t2.j.b(this.f2423g, eVar.f2423g) && t2.j.b(this.f2424h, eVar.f2424h) && t2.j.b(this.f2425i, eVar.f2425i) && t2.j.b(this.f2426j, eVar.f2426j) && t2.j.b(this.f2427k, eVar.f2427k) && t2.j.b(this.f2428l, eVar.f2428l) && t2.j.b(this.f2429m, eVar.f2429m);
    }

    public int hashCode() {
        W w3 = this.f2417a;
        int iHashCode = (w3 == null ? 0 : w3.hashCode()) * 31;
        W w4 = this.f2418b;
        int iHashCode2 = (iHashCode + (w4 == null ? 0 : w4.hashCode())) * 31;
        W w5 = this.f2419c;
        int iHashCode3 = (iHashCode2 + (w5 == null ? 0 : w5.hashCode())) * 31;
        W w6 = this.f2420d;
        int iHashCode4 = (iHashCode3 + (w6 == null ? 0 : w6.hashCode())) * 31;
        W w7 = this.f2421e;
        int iHashCode5 = (iHashCode4 + (w7 == null ? 0 : w7.hashCode())) * 31;
        W w8 = this.f2422f;
        int iHashCode6 = (iHashCode5 + (w8 == null ? 0 : w8.hashCode())) * 31;
        W w9 = this.f2423g;
        int iHashCode7 = (iHashCode6 + (w9 == null ? 0 : w9.hashCode())) * 31;
        W w10 = this.f2424h;
        int iHashCode8 = (iHashCode7 + (w10 == null ? 0 : w10.hashCode())) * 31;
        W w11 = this.f2425i;
        int iHashCode9 = (iHashCode8 + (w11 == null ? 0 : w11.hashCode())) * 31;
        W w12 = this.f2426j;
        int iHashCode10 = (iHashCode9 + (w12 == null ? 0 : w12.hashCode())) * 31;
        W w13 = this.f2427k;
        int iHashCode11 = (iHashCode10 + (w13 == null ? 0 : w13.hashCode())) * 31;
        W w14 = this.f2428l;
        int iHashCode12 = (iHashCode11 + (w14 == null ? 0 : w14.hashCode())) * 31;
        W w15 = this.f2429m;
        return iHashCode12 + (w15 != null ? w15.hashCode() : 0);
    }

    public String toString() {
        return "BorderRadiusStyle(uniform=" + this.f2417a + ", topLeft=" + this.f2418b + ", topRight=" + this.f2419c + ", bottomLeft=" + this.f2420d + ", bottomRight=" + this.f2421e + ", topStart=" + this.f2422f + ", topEnd=" + this.f2423g + ", bottomStart=" + this.f2424h + ", bottomEnd=" + this.f2425i + ", startStart=" + this.f2426j + ", startEnd=" + this.f2427k + ", endStart=" + this.f2428l + ", endEnd=" + this.f2429m + ")";
    }

    public e(W w3, W w4, W w5, W w6, W w7, W w8, W w9, W w10, W w11, W w12, W w13, W w14, W w15) {
        this.f2417a = w3;
        this.f2418b = w4;
        this.f2419c = w5;
        this.f2420d = w6;
        this.f2421e = w7;
        this.f2422f = w8;
        this.f2423g = w9;
        this.f2424h = w10;
        this.f2425i = w11;
        this.f2426j = w12;
        this.f2427k = w13;
        this.f2428l = w14;
        this.f2429m = w15;
    }

    public /* synthetic */ e(W w3, W w4, W w5, W w6, W w7, W w8, W w9, W w10, W w11, W w12, W w13, W w14, W w15, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? null : w3, (i3 & 2) != 0 ? null : w4, (i3 & 4) != 0 ? null : w5, (i3 & 8) != 0 ? null : w6, (i3 & 16) != 0 ? null : w7, (i3 & 32) != 0 ? null : w8, (i3 & 64) != 0 ? null : w9, (i3 & 128) != 0 ? null : w10, (i3 & 256) != 0 ? null : w11, (i3 & 512) != 0 ? null : w12, (i3 & 1024) != 0 ? null : w13, (i3 & 2048) != 0 ? null : w14, (i3 & 4096) == 0 ? w15 : null);
    }
}
