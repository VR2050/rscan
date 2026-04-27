package com.th3rdwave.safeareacontext;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f8733a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float f8734b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final float f8735c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final float f8736d;

    public a(float f3, float f4, float f5, float f6) {
        this.f8733a = f3;
        this.f8734b = f4;
        this.f8735c = f5;
        this.f8736d = f6;
    }

    public final float a() {
        return this.f8735c;
    }

    public final float b() {
        return this.f8736d;
    }

    public final float c() {
        return this.f8734b;
    }

    public final float d() {
        return this.f8733a;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Float.compare(this.f8733a, aVar.f8733a) == 0 && Float.compare(this.f8734b, aVar.f8734b) == 0 && Float.compare(this.f8735c, aVar.f8735c) == 0 && Float.compare(this.f8736d, aVar.f8736d) == 0;
    }

    public int hashCode() {
        return (((((Float.hashCode(this.f8733a) * 31) + Float.hashCode(this.f8734b)) * 31) + Float.hashCode(this.f8735c)) * 31) + Float.hashCode(this.f8736d);
    }

    public String toString() {
        return "EdgeInsets(top=" + this.f8733a + ", right=" + this.f8734b + ", bottom=" + this.f8735c + ", left=" + this.f8736d + ")";
    }
}
