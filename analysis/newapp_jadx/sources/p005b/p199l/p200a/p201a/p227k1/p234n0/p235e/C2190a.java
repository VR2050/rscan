package p005b.p199l.p200a.p201a.p227k1.p234n0.p235e;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.List;
import java.util.UUID;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1990j;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.n0.e.a */
/* loaded from: classes.dex */
public class C2190a {

    /* renamed from: a */
    public final int f5155a;

    /* renamed from: b */
    public final int f5156b;

    /* renamed from: c */
    public final int f5157c;

    /* renamed from: d */
    public final boolean f5158d;

    /* renamed from: e */
    @Nullable
    public final a f5159e;

    /* renamed from: f */
    public final b[] f5160f;

    /* renamed from: g */
    public final long f5161g;

    /* renamed from: h */
    public final long f5162h;

    /* renamed from: b.l.a.a.k1.n0.e.a$a */
    public static class a {

        /* renamed from: a */
        public final UUID f5163a;

        /* renamed from: b */
        public final byte[] f5164b;

        /* renamed from: c */
        public final C1990j[] f5165c;

        public a(UUID uuid, byte[] bArr, C1990j[] c1990jArr) {
            this.f5163a = uuid;
            this.f5164b = bArr;
            this.f5165c = c1990jArr;
        }
    }

    /* renamed from: b.l.a.a.k1.n0.e.a$b */
    public static class b {

        /* renamed from: a */
        public final int f5166a;

        /* renamed from: b */
        public final String f5167b;

        /* renamed from: c */
        public final long f5168c;

        /* renamed from: d */
        public final String f5169d;

        /* renamed from: e */
        public final int f5170e;

        /* renamed from: f */
        public final int f5171f;

        /* renamed from: g */
        public final int f5172g;

        /* renamed from: h */
        public final int f5173h;

        /* renamed from: i */
        @Nullable
        public final String f5174i;

        /* renamed from: j */
        public final Format[] f5175j;

        /* renamed from: k */
        public final int f5176k;

        /* renamed from: l */
        public final String f5177l;

        /* renamed from: m */
        public final String f5178m;

        /* renamed from: n */
        public final List<Long> f5179n;

        /* renamed from: o */
        public final long[] f5180o;

        /* renamed from: p */
        public final long f5181p;

        public b(String str, String str2, int i2, String str3, long j2, String str4, int i3, int i4, int i5, int i6, @Nullable String str5, Format[] formatArr, List<Long> list, long[] jArr, long j3) {
            this.f5177l = str;
            this.f5178m = str2;
            this.f5166a = i2;
            this.f5167b = str3;
            this.f5168c = j2;
            this.f5169d = str4;
            this.f5170e = i3;
            this.f5171f = i4;
            this.f5172g = i5;
            this.f5173h = i6;
            this.f5174i = str5;
            this.f5175j = formatArr;
            this.f5179n = list;
            this.f5180o = jArr;
            this.f5181p = j3;
            this.f5176k = list.size();
        }

        /* renamed from: a */
        public long m2005a(int i2) {
            if (i2 == this.f5176k - 1) {
                return this.f5181p;
            }
            long[] jArr = this.f5180o;
            return jArr[i2 + 1] - jArr[i2];
        }

        /* renamed from: b */
        public int m2006b(long j2) {
            return C2344d0.m2326d(this.f5180o, j2, true, true);
        }
    }

    public C2190a(int i2, int i3, long j2, long j3, long j4, int i4, boolean z, @Nullable a aVar, b[] bVarArr) {
        long m2314F = j3 == 0 ? -9223372036854775807L : C2344d0.m2314F(j3, 1000000L, j2);
        long m2314F2 = j4 != 0 ? C2344d0.m2314F(j4, 1000000L, j2) : -9223372036854775807L;
        this.f5155a = i2;
        this.f5156b = i3;
        this.f5161g = m2314F;
        this.f5162h = m2314F2;
        this.f5157c = i4;
        this.f5158d = z;
        this.f5159e = aVar;
        this.f5160f = bVarArr;
    }
}
