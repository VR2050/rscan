package P2;

import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final a f2277g = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final boolean f2278a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final Integer f2279b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public final boolean f2280c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public final Integer f2281d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public final boolean f2282e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public final boolean f2283f;

    public static final class a {
        private a() {
        }

        /* JADX WARN: Removed duplicated region for block: B:28:0x008b A[PHI: r7 r9
          0x008b: PHI (r7v6 java.lang.Integer) = (r7v4 java.lang.Integer), (r7v4 java.lang.Integer), (r7v7 java.lang.Integer) binds: [B:47:0x00ba, B:44:0x00b1, B:27:0x0089] A[DONT_GENERATE, DONT_INLINE]
          0x008b: PHI (r9v7 java.lang.Integer) = (r9v4 java.lang.Integer), (r9v5 java.lang.Integer), (r9v4 java.lang.Integer) binds: [B:47:0x00ba, B:44:0x00b1, B:27:0x0089] A[DONT_GENERATE, DONT_INLINE]] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final P2.e a(B2.t r21) {
            /*
                Method dump skipped, instruction units count: 216
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: P2.e.a.a(B2.t):P2.e");
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public e(boolean z3, Integer num, boolean z4, Integer num2, boolean z5, boolean z6) {
        this.f2278a = z3;
        this.f2279b = num;
        this.f2280c = z4;
        this.f2281d = num2;
        this.f2282e = z5;
        this.f2283f = z6;
    }

    public final boolean a(boolean z3) {
        return z3 ? this.f2280c : this.f2282e;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.f2278a == eVar.f2278a && j.b(this.f2279b, eVar.f2279b) && this.f2280c == eVar.f2280c && j.b(this.f2281d, eVar.f2281d) && this.f2282e == eVar.f2282e && this.f2283f == eVar.f2283f;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [int] */
    /* JADX WARN: Type inference failed for: r0v12 */
    /* JADX WARN: Type inference failed for: r0v13 */
    /* JADX WARN: Type inference failed for: r1v0 */
    /* JADX WARN: Type inference failed for: r1v1, types: [int] */
    /* JADX WARN: Type inference failed for: r1v2 */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v12 */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v4, types: [int] */
    /* JADX WARN: Type inference failed for: r2v7, types: [int] */
    /* JADX WARN: Type inference failed for: r2v9 */
    public int hashCode() {
        boolean z3 = this.f2278a;
        ?? r02 = z3;
        if (z3) {
            r02 = 1;
        }
        int i3 = r02 * 31;
        Integer num = this.f2279b;
        int iHashCode = (i3 + (num != null ? num.hashCode() : 0)) * 31;
        boolean z4 = this.f2280c;
        ?? r22 = z4;
        if (z4) {
            r22 = 1;
        }
        int i4 = (iHashCode + r22) * 31;
        Integer num2 = this.f2281d;
        int iHashCode2 = (i4 + (num2 != null ? num2.hashCode() : 0)) * 31;
        boolean z5 = this.f2282e;
        ?? r23 = z5;
        if (z5) {
            r23 = 1;
        }
        int i5 = (iHashCode2 + r23) * 31;
        boolean z6 = this.f2283f;
        return i5 + (z6 ? 1 : z6);
    }

    public String toString() {
        return "WebSocketExtensions(perMessageDeflate=" + this.f2278a + ", clientMaxWindowBits=" + this.f2279b + ", clientNoContextTakeover=" + this.f2280c + ", serverMaxWindowBits=" + this.f2281d + ", serverNoContextTakeover=" + this.f2282e + ", unknownValues=" + this.f2283f + ")";
    }
}
