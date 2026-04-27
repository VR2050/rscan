package com.facebook.react.modules.network;

import B2.C;
import B2.x;
import Q2.AbstractC0207c;
import Q2.D;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/* JADX INFO: loaded from: classes.dex */
public final class j extends C {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C f7139b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final i f7140c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private long f7141d;

    public j(C c3, i iVar) {
        t2.j.f(c3, "requestBody");
        t2.j.f(iVar, "progressListener");
        this.f7139b = c3;
        this.f7140c = iVar;
    }

    private final D j(Q2.j jVar) {
        return AbstractC0207c.a().b(new a(jVar.l0()));
    }

    @Override // B2.C
    public long a() {
        if (this.f7141d == 0) {
            this.f7141d = this.f7139b.a();
        }
        return this.f7141d;
    }

    @Override // B2.C
    public x b() {
        return this.f7139b.b();
    }

    @Override // B2.C
    public void h(Q2.j jVar) {
        t2.j.f(jVar, "sink");
        Q2.j jVarA = AbstractC0207c.a().a(j(jVar));
        a();
        this.f7139b.h(jVarA);
        jVarA.flush();
    }

    public static final class a extends FilterOutputStream {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private long f7142b;

        a(OutputStream outputStream) {
            super(outputStream);
        }

        public final void b() {
            long j3 = this.f7142b;
            long jA = j.this.a();
            j.this.f7140c.a(j3, jA, j3 == jA);
        }

        @Override // java.io.FilterOutputStream, java.io.OutputStream
        public void write(byte[] bArr, int i3, int i4) throws IOException {
            t2.j.f(bArr, "data");
            super.write(bArr, i3, i4);
            this.f7142b += (long) i4;
            b();
        }

        @Override // java.io.FilterOutputStream, java.io.OutputStream
        public void write(int i3) throws IOException {
            super.write(i3);
            this.f7142b++;
            b();
        }
    }
}
