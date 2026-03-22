package p005b.p199l.p200a.p201a.p227k1.p232m0.p233s;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.drm.DrmInitData;
import java.util.Collections;
import java.util.List;

/* renamed from: b.l.a.a.k1.m0.s.e */
/* loaded from: classes.dex */
public final class C2180e extends AbstractC2181f {

    /* renamed from: d */
    public final int f5059d;

    /* renamed from: e */
    public final long f5060e;

    /* renamed from: f */
    public final long f5061f;

    /* renamed from: g */
    public final boolean f5062g;

    /* renamed from: h */
    public final int f5063h;

    /* renamed from: i */
    public final long f5064i;

    /* renamed from: j */
    public final int f5065j;

    /* renamed from: k */
    public final long f5066k;

    /* renamed from: l */
    public final boolean f5067l;

    /* renamed from: m */
    public final boolean f5068m;

    /* renamed from: n */
    @Nullable
    public final DrmInitData f5069n;

    /* renamed from: o */
    public final List<a> f5070o;

    /* renamed from: p */
    public final long f5071p;

    /* renamed from: b.l.a.a.k1.m0.s.e$a */
    public static final class a implements Comparable<Long> {

        /* renamed from: c */
        public final String f5072c;

        /* renamed from: e */
        @Nullable
        public final a f5073e;

        /* renamed from: f */
        public final long f5074f;

        /* renamed from: g */
        public final int f5075g;

        /* renamed from: h */
        public final long f5076h;

        /* renamed from: i */
        @Nullable
        public final DrmInitData f5077i;

        /* renamed from: j */
        @Nullable
        public final String f5078j;

        /* renamed from: k */
        @Nullable
        public final String f5079k;

        /* renamed from: l */
        public final long f5080l;

        /* renamed from: m */
        public final long f5081m;

        /* renamed from: n */
        public final boolean f5082n;

        public a(String str, @Nullable a aVar, String str2, long j2, int i2, long j3, @Nullable DrmInitData drmInitData, @Nullable String str3, @Nullable String str4, long j4, long j5, boolean z) {
            this.f5072c = str;
            this.f5073e = aVar;
            this.f5074f = j2;
            this.f5075g = i2;
            this.f5076h = j3;
            this.f5077i = drmInitData;
            this.f5078j = str3;
            this.f5079k = str4;
            this.f5080l = j4;
            this.f5081m = j5;
            this.f5082n = z;
        }

        @Override // java.lang.Comparable
        public int compareTo(Long l2) {
            Long l3 = l2;
            if (this.f5076h > l3.longValue()) {
                return 1;
            }
            return this.f5076h < l3.longValue() ? -1 : 0;
        }
    }

    public C2180e(int i2, String str, List<String> list, long j2, long j3, boolean z, int i3, long j4, int i4, long j5, boolean z2, boolean z3, boolean z4, @Nullable DrmInitData drmInitData, List<a> list2) {
        super(str, list, z2);
        this.f5059d = i2;
        this.f5061f = j3;
        this.f5062g = z;
        this.f5063h = i3;
        this.f5064i = j4;
        this.f5065j = i4;
        this.f5066k = j5;
        this.f5067l = z3;
        this.f5068m = z4;
        this.f5069n = drmInitData;
        this.f5070o = Collections.unmodifiableList(list2);
        if (list2.isEmpty()) {
            this.f5071p = 0L;
        } else {
            a aVar = list2.get(list2.size() - 1);
            this.f5071p = aVar.f5076h + aVar.f5074f;
        }
        this.f5060e = j2 == -9223372036854775807L ? -9223372036854775807L : j2 >= 0 ? j2 : this.f5071p + j2;
    }
}
