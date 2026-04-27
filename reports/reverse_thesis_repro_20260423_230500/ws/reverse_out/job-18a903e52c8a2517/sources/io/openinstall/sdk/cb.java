package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class cb implements Cloneable {
    private final cg a;
    private final cf b;

    public cb(cf cfVar, cg cgVar) {
        this.a = cgVar;
        this.b = cfVar;
    }

    public cb(cg cgVar) {
        this(null, cgVar);
    }

    public cg a() {
        return this.a;
    }

    public void a(byte[] bArr) {
        cf cfVar = this.b;
        if (cfVar != null) {
            cfVar.a(bArr);
        } else {
            this.a.a(bArr);
        }
    }

    public cf b() {
        return this.b;
    }

    public byte[] c() {
        cf cfVar = this.b;
        return cfVar != null ? cfVar.d() : this.a.g;
    }

    /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
    public cb clone() {
        cf cfVar = this.b;
        return new cb(cfVar == null ? null : cfVar.clone(), this.a.clone());
    }
}
