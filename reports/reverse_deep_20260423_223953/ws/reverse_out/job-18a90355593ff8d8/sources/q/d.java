package q;

/* JADX INFO: loaded from: classes.dex */
public class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final Object f9844a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final Object f9845b;

    public d(Object obj, Object obj2) {
        this.f9844a = obj;
        this.f9845b = obj2;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return c.a(dVar.f9844a, this.f9844a) && c.a(dVar.f9845b, this.f9845b);
    }

    public int hashCode() {
        Object obj = this.f9844a;
        int iHashCode = obj == null ? 0 : obj.hashCode();
        Object obj2 = this.f9845b;
        return iHashCode ^ (obj2 != null ? obj2.hashCode() : 0);
    }

    public String toString() {
        return "Pair{" + this.f9844a + " " + this.f9845b + "}";
    }
}
