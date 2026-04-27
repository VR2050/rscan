package com.facebook.imagepipeline.memory;

import Q0.w;
import Q0.y;
import a0.k;
import b0.AbstractC0311a;
import java.io.IOException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class f extends k {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final e f6066b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private AbstractC0311a f6067c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f6068d;

    public static final class a extends RuntimeException {
        public a() {
            super("OutputStream no longer valid");
        }
    }

    public /* synthetic */ f(e eVar, int i3, int i4, DefaultConstructorMarker defaultConstructorMarker) {
        this(eVar, (i4 & 2) != 0 ? eVar.B() : i3);
    }

    private final void i() {
        if (!AbstractC0311a.d0(this.f6067c)) {
            throw new a();
        }
    }

    @Override // a0.k, java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws Throwable {
        AbstractC0311a.D(this.f6067c);
        this.f6067c = null;
        this.f6068d = -1;
        super.close();
    }

    public final void p(int i3) throws Throwable {
        i();
        AbstractC0311a abstractC0311a = this.f6067c;
        if (abstractC0311a == null) {
            throw new IllegalStateException("Required value was null.");
        }
        j.c(abstractC0311a);
        if (i3 <= ((w) abstractC0311a.P()).i()) {
            return;
        }
        Object obj = this.f6066b.get(i3);
        j.e(obj, "get(...)");
        w wVar = (w) obj;
        AbstractC0311a abstractC0311a2 = this.f6067c;
        if (abstractC0311a2 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        j.c(abstractC0311a2);
        ((w) abstractC0311a2.P()).y(0, wVar, 0, this.f6068d);
        AbstractC0311a abstractC0311a3 = this.f6067c;
        j.c(abstractC0311a3);
        abstractC0311a3.close();
        this.f6067c = AbstractC0311a.n0(wVar, this.f6066b);
    }

    @Override // a0.k
    /* JADX INFO: renamed from: r, reason: merged with bridge method [inline-methods] */
    public y b() {
        i();
        AbstractC0311a abstractC0311a = this.f6067c;
        if (abstractC0311a != null) {
            return new y(abstractC0311a, this.f6068d);
        }
        throw new IllegalStateException("Required value was null.");
    }

    @Override // a0.k
    public int size() {
        return this.f6068d;
    }

    @Override // java.io.OutputStream
    public void write(int i3) throws IOException {
        write(new byte[]{(byte) i3});
    }

    public f(e eVar, int i3) {
        j.f(eVar, "pool");
        if (i3 > 0) {
            this.f6066b = eVar;
            this.f6068d = 0;
            this.f6067c = AbstractC0311a.n0(eVar.get(i3), eVar);
            return;
        }
        throw new IllegalStateException("Check failed.");
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i3, int i4) throws Throwable {
        j.f(bArr, "buffer");
        if (i3 >= 0 && i4 >= 0 && i3 + i4 <= bArr.length) {
            i();
            p(this.f6068d + i4);
            AbstractC0311a abstractC0311a = this.f6067c;
            if (abstractC0311a != null) {
                ((w) abstractC0311a.P()).v(this.f6068d, bArr, i3, i4);
                this.f6068d += i4;
                return;
            }
            throw new IllegalStateException("Required value was null.");
        }
        throw new ArrayIndexOutOfBoundsException("length=" + bArr.length + "; regionStart=" + i3 + "; regionLength=" + i4);
    }
}
