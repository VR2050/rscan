package com.th3rdwave.safeareacontext;

/* JADX INFO: loaded from: classes.dex */
public final class m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final l f8762a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final l f8763b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final l f8764c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final l f8765d;

    public m(l lVar, l lVar2, l lVar3, l lVar4) {
        t2.j.f(lVar, "top");
        t2.j.f(lVar2, "right");
        t2.j.f(lVar3, "bottom");
        t2.j.f(lVar4, "left");
        this.f8762a = lVar;
        this.f8763b = lVar2;
        this.f8764c = lVar3;
        this.f8765d = lVar4;
    }

    public final l a() {
        return this.f8764c;
    }

    public final l b() {
        return this.f8765d;
    }

    public final l c() {
        return this.f8763b;
    }

    public final l d() {
        return this.f8762a;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return this.f8762a == mVar.f8762a && this.f8763b == mVar.f8763b && this.f8764c == mVar.f8764c && this.f8765d == mVar.f8765d;
    }

    public int hashCode() {
        return (((((this.f8762a.hashCode() * 31) + this.f8763b.hashCode()) * 31) + this.f8764c.hashCode()) * 31) + this.f8765d.hashCode();
    }

    public String toString() {
        return "SafeAreaViewEdges(top=" + this.f8762a + ", right=" + this.f8763b + ", bottom=" + this.f8764c + ", left=" + this.f8765d + ")";
    }
}
