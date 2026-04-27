package N0;

/* JADX INFO: loaded from: classes.dex */
public class n implements o {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final o f1902d = d(Integer.MAX_VALUE, true, true);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    int f1903a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    boolean f1904b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    boolean f1905c;

    private n(int i3, boolean z3, boolean z4) {
        this.f1903a = i3;
        this.f1904b = z3;
        this.f1905c = z4;
    }

    public static o d(int i3, boolean z3, boolean z4) {
        return new n(i3, z3, z4);
    }

    @Override // N0.o
    public boolean a() {
        return this.f1905c;
    }

    @Override // N0.o
    public boolean b() {
        return this.f1904b;
    }

    @Override // N0.o
    public int c() {
        return this.f1903a;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return this.f1903a == nVar.f1903a && this.f1904b == nVar.f1904b && this.f1905c == nVar.f1905c;
    }

    public int hashCode() {
        return (this.f1903a ^ (this.f1904b ? 4194304 : 0)) ^ (this.f1905c ? 8388608 : 0);
    }
}
