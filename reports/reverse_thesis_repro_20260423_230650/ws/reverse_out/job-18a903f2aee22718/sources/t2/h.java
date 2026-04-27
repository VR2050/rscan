package t2;

/* JADX INFO: loaded from: classes.dex */
public abstract class h extends c implements g, x2.d {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f10207i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int f10208j;

    public h(int i3, Object obj, Class cls, String str, String str2, int i4) {
        super(obj, cls, str, str2, (i4 & 1) == 1);
        this.f10207i = i3;
        this.f10208j = i4 >> 1;
    }

    @Override // t2.c
    protected x2.a e() {
        return u.a(this);
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof h) {
            h hVar = (h) obj;
            return g().equals(hVar.g()) && j().equals(hVar.j()) && this.f10208j == hVar.f10208j && this.f10207i == hVar.f10207i && j.b(f(), hVar.f()) && j.b(h(), hVar.h());
        }
        if (obj instanceof x2.d) {
            return obj.equals(b());
        }
        return false;
    }

    public int hashCode() {
        return (((h() == null ? 0 : h().hashCode() * 31) + g().hashCode()) * 31) + j().hashCode();
    }

    public String toString() {
        x2.a aVarB = b();
        if (aVarB != this) {
            return aVarB.toString();
        }
        if ("<init>".equals(g())) {
            return "constructor (Kotlin reflection is not available)";
        }
        return "function " + g() + " (Kotlin reflection is not available)";
    }
}
