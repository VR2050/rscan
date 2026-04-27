package t2;

/* JADX INFO: loaded from: classes.dex */
public abstract class p extends c implements x2.g {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final boolean f10212i;

    public p(Object obj, Class cls, String str, String str2, int i3) {
        super(obj, cls, str, str2, (i3 & 1) == 1);
        this.f10212i = (i3 & 2) == 2;
    }

    @Override // t2.c
    public x2.a b() {
        return this.f10212i ? this : super.b();
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof p) {
            p pVar = (p) obj;
            return h().equals(pVar.h()) && g().equals(pVar.g()) && j().equals(pVar.j()) && j.b(f(), pVar.f());
        }
        if (obj instanceof x2.g) {
            return obj.equals(b());
        }
        return false;
    }

    public int hashCode() {
        return (((h().hashCode() * 31) + g().hashCode()) * 31) + j().hashCode();
    }

    protected x2.g k() {
        if (this.f10212i) {
            throw new UnsupportedOperationException("Kotlin reflection is not yet supported for synthetic Java properties. Please follow/upvote https://youtrack.jetbrains.com/issue/KT-55980");
        }
        return (x2.g) super.i();
    }

    public String toString() {
        x2.a aVarB = b();
        if (aVarB != this) {
            return aVarB.toString();
        }
        return "property " + g() + " (Kotlin reflection is not available)";
    }
}
