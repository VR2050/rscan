package J2;

import Q2.l;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final Q2.l f1475d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final Q2.l f1476e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final Q2.l f1477f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final Q2.l f1478g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final Q2.l f1479h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final Q2.l f1480i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final a f1481j = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final int f1482a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final Q2.l f1483b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public final Q2.l f1484c;

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static {
        l.a aVar = Q2.l.f2556f;
        f1475d = aVar.e(":");
        f1476e = aVar.e(":status");
        f1477f = aVar.e(":method");
        f1478g = aVar.e(":path");
        f1479h = aVar.e(":scheme");
        f1480i = aVar.e(":authority");
    }

    public c(Q2.l lVar, Q2.l lVar2) {
        t2.j.f(lVar, "name");
        t2.j.f(lVar2, "value");
        this.f1483b = lVar;
        this.f1484c = lVar2;
        this.f1482a = lVar.v() + 32 + lVar2.v();
    }

    public final Q2.l a() {
        return this.f1483b;
    }

    public final Q2.l b() {
        return this.f1484c;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return t2.j.b(this.f1483b, cVar.f1483b) && t2.j.b(this.f1484c, cVar.f1484c);
    }

    public int hashCode() {
        Q2.l lVar = this.f1483b;
        int iHashCode = (lVar != null ? lVar.hashCode() : 0) * 31;
        Q2.l lVar2 = this.f1484c;
        return iHashCode + (lVar2 != null ? lVar2.hashCode() : 0);
    }

    public String toString() {
        return this.f1483b.z() + ": " + this.f1484c.z();
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public c(String str, String str2) {
        t2.j.f(str, "name");
        t2.j.f(str2, "value");
        l.a aVar = Q2.l.f2556f;
        this(aVar.e(str), aVar.e(str2));
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public c(Q2.l lVar, String str) {
        this(lVar, Q2.l.f2556f.e(str));
        t2.j.f(lVar, "name");
        t2.j.f(str, "value");
    }
}
