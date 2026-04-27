package h2;

import java.io.Serializable;

/* JADX INFO: renamed from: h2.i, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0563i implements Serializable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Object f9274b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Object f9275c;

    public C0563i(Object obj, Object obj2) {
        this.f9274b = obj;
        this.f9275c = obj2;
    }

    public final Object a() {
        return this.f9274b;
    }

    public final Object b() {
        return this.f9275c;
    }

    public final Object c() {
        return this.f9274b;
    }

    public final Object d() {
        return this.f9275c;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0563i)) {
            return false;
        }
        C0563i c0563i = (C0563i) obj;
        return t2.j.b(this.f9274b, c0563i.f9274b) && t2.j.b(this.f9275c, c0563i.f9275c);
    }

    public int hashCode() {
        Object obj = this.f9274b;
        int iHashCode = (obj == null ? 0 : obj.hashCode()) * 31;
        Object obj2 = this.f9275c;
        return iHashCode + (obj2 != null ? obj2.hashCode() : 0);
    }

    public String toString() {
        return '(' + this.f9274b + ", " + this.f9275c + ')';
    }
}
