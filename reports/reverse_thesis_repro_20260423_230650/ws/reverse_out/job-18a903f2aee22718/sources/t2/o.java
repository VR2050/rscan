package t2;

/* JADX INFO: loaded from: classes.dex */
public final class o implements d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Class f10210a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f10211b;

    public o(Class cls, String str) {
        j.f(cls, "jClass");
        j.f(str, "moduleName");
        this.f10210a = cls;
        this.f10211b = str;
    }

    @Override // t2.d
    public Class a() {
        return this.f10210a;
    }

    public boolean equals(Object obj) {
        return (obj instanceof o) && j.b(a(), ((o) obj).a());
    }

    public int hashCode() {
        return a().hashCode();
    }

    public String toString() {
        return a().toString() + " (Kotlin reflection is not available)";
    }
}
