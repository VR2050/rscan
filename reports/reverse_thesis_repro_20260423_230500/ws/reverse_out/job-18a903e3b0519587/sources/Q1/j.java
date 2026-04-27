package Q1;

/* JADX INFO: loaded from: classes.dex */
public final class j {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final k f2451a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final k f2452b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final k f2453c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final k f2454d;

    public j(k kVar, k kVar2, k kVar3, k kVar4) {
        t2.j.f(kVar, "topLeft");
        t2.j.f(kVar2, "topRight");
        t2.j.f(kVar3, "bottomLeft");
        t2.j.f(kVar4, "bottomRight");
        this.f2451a = kVar;
        this.f2452b = kVar2;
        this.f2453c = kVar3;
        this.f2454d = kVar4;
    }

    public final k a() {
        return this.f2453c;
    }

    public final k b() {
        return this.f2454d;
    }

    public final k c() {
        return this.f2451a;
    }

    public final k d() {
        return this.f2452b;
    }

    public final boolean e() {
        return this.f2451a.a() > 0.0f || this.f2451a.b() > 0.0f || this.f2452b.a() > 0.0f || this.f2452b.b() > 0.0f || this.f2453c.a() > 0.0f || this.f2453c.b() > 0.0f || this.f2454d.a() > 0.0f;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return t2.j.b(this.f2451a, jVar.f2451a) && t2.j.b(this.f2452b, jVar.f2452b) && t2.j.b(this.f2453c, jVar.f2453c) && t2.j.b(this.f2454d, jVar.f2454d);
    }

    public final boolean f() {
        return t2.j.b(this.f2451a, this.f2452b) && t2.j.b(this.f2451a, this.f2453c) && t2.j.b(this.f2451a, this.f2454d);
    }

    public int hashCode() {
        return (((((this.f2451a.hashCode() * 31) + this.f2452b.hashCode()) * 31) + this.f2453c.hashCode()) * 31) + this.f2454d.hashCode();
    }

    public String toString() {
        return "ComputedBorderRadius(topLeft=" + this.f2451a + ", topRight=" + this.f2452b + ", bottomLeft=" + this.f2453c + ", bottomRight=" + this.f2454d + ")";
    }

    public j() {
        this(new k(0.0f, 0.0f), new k(0.0f, 0.0f), new k(0.0f, 0.0f), new k(0.0f, 0.0f));
    }
}
