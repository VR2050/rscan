package com.th3rdwave.safeareacontext;

/* JADX INFO: loaded from: classes.dex */
public final class n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final a f8766a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final o f8767b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final m f8768c;

    public n(a aVar, o oVar, m mVar) {
        t2.j.f(aVar, "insets");
        t2.j.f(oVar, "mode");
        t2.j.f(mVar, "edges");
        this.f8766a = aVar;
        this.f8767b = oVar;
        this.f8768c = mVar;
    }

    public final m a() {
        return this.f8768c;
    }

    public final a b() {
        return this.f8766a;
    }

    public final o c() {
        return this.f8767b;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return t2.j.b(this.f8766a, nVar.f8766a) && this.f8767b == nVar.f8767b && t2.j.b(this.f8768c, nVar.f8768c);
    }

    public int hashCode() {
        return (((this.f8766a.hashCode() * 31) + this.f8767b.hashCode()) * 31) + this.f8768c.hashCode();
    }

    public String toString() {
        return "SafeAreaViewLocalData(insets=" + this.f8766a + ", mode=" + this.f8767b + ", edges=" + this.f8768c + ")";
    }
}
