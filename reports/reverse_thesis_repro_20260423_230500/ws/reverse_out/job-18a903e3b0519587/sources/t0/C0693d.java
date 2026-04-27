package t0;

import java.util.Arrays;

/* JADX INFO: renamed from: t0.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0693d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private a f10165a = a.BITMAP_ONLY;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f10166b = false;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float[] f10167c = null;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f10168d = 0;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private float f10169e = 0.0f;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f10170f = 0;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private float f10171g = 0.0f;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f10172h = false;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f10173i = false;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f10174j = false;

    /* JADX INFO: renamed from: t0.d$a */
    public enum a {
        OVERLAY_COLOR,
        BITMAP_ONLY
    }

    public static C0693d a(float f3) {
        return new C0693d().m(f3);
    }

    private float[] e() {
        if (this.f10167c == null) {
            this.f10167c = new float[8];
        }
        return this.f10167c;
    }

    public int b() {
        return this.f10170f;
    }

    public float c() {
        return this.f10169e;
    }

    public float[] d() {
        return this.f10167c;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        C0693d c0693d = (C0693d) obj;
        if (this.f10166b == c0693d.f10166b && this.f10168d == c0693d.f10168d && Float.compare(c0693d.f10169e, this.f10169e) == 0 && this.f10170f == c0693d.f10170f && Float.compare(c0693d.f10171g, this.f10171g) == 0 && this.f10165a == c0693d.f10165a && this.f10172h == c0693d.f10172h && this.f10173i == c0693d.f10173i) {
            return Arrays.equals(this.f10167c, c0693d.f10167c);
        }
        return false;
    }

    public int f() {
        return this.f10168d;
    }

    public float g() {
        return this.f10171g;
    }

    public boolean h() {
        return this.f10173i;
    }

    public int hashCode() {
        a aVar = this.f10165a;
        int iHashCode = (((aVar != null ? aVar.hashCode() : 0) * 31) + (this.f10166b ? 1 : 0)) * 31;
        float[] fArr = this.f10167c;
        int iHashCode2 = (((iHashCode + (fArr != null ? Arrays.hashCode(fArr) : 0)) * 31) + this.f10168d) * 31;
        float f3 = this.f10169e;
        int iFloatToIntBits = (((iHashCode2 + (f3 != 0.0f ? Float.floatToIntBits(f3) : 0)) * 31) + this.f10170f) * 31;
        float f4 = this.f10171g;
        return ((((iFloatToIntBits + (f4 != 0.0f ? Float.floatToIntBits(f4) : 0)) * 31) + (this.f10172h ? 1 : 0)) * 31) + (this.f10173i ? 1 : 0);
    }

    public boolean i() {
        return this.f10174j;
    }

    public boolean j() {
        return this.f10166b;
    }

    public a k() {
        return this.f10165a;
    }

    public boolean l() {
        return this.f10172h;
    }

    public C0693d m(float f3) {
        Arrays.fill(e(), f3);
        return this;
    }

    public C0693d n(int i3) {
        this.f10168d = i3;
        this.f10165a = a.OVERLAY_COLOR;
        return this;
    }

    public C0693d o(boolean z3) {
        this.f10173i = z3;
        return this;
    }

    public C0693d p(a aVar) {
        this.f10165a = aVar;
        return this;
    }
}
