package com.th3rdwave.safeareacontext;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f8740a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float f8741b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final float f8742c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final float f8743d;

    public c(float f3, float f4, float f5, float f6) {
        this.f8740a = f3;
        this.f8741b = f4;
        this.f8742c = f5;
        this.f8743d = f6;
    }

    public final float a() {
        return this.f8743d;
    }

    public final float b() {
        return this.f8742c;
    }

    public final float c() {
        return this.f8740a;
    }

    public final float d() {
        return this.f8741b;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Float.compare(this.f8740a, cVar.f8740a) == 0 && Float.compare(this.f8741b, cVar.f8741b) == 0 && Float.compare(this.f8742c, cVar.f8742c) == 0 && Float.compare(this.f8743d, cVar.f8743d) == 0;
    }

    public int hashCode() {
        return (((((Float.hashCode(this.f8740a) * 31) + Float.hashCode(this.f8741b)) * 31) + Float.hashCode(this.f8742c)) * 31) + Float.hashCode(this.f8743d);
    }

    public String toString() {
        return "Rect(x=" + this.f8740a + ", y=" + this.f8741b + ", width=" + this.f8742c + ", height=" + this.f8743d + ")";
    }
}
