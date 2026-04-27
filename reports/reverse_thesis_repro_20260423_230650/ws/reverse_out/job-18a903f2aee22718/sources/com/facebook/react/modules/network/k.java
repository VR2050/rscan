package com.facebook.react.modules.network;

import B2.E;
import B2.x;
import Q2.F;
import Q2.t;

/* JADX INFO: loaded from: classes.dex */
public class k extends E {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final E f7144c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final i f7145d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Q2.k f7146e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private long f7147f = 0;

    class a extends Q2.o {
        a(F f3) {
            super(f3);
        }

        @Override // Q2.o, Q2.F
        public long R(Q2.i iVar, long j3) {
            long jR = super.R(iVar, j3);
            k.this.f7147f += jR != -1 ? jR : 0L;
            k.this.f7145d.a(k.this.f7147f, k.this.f7144c.r(), jR == -1);
            return jR;
        }
    }

    public k(E e3, i iVar) {
        this.f7144c = e3;
        this.f7145d = iVar;
    }

    private F d0(F f3) {
        return new a(f3);
    }

    public long e0() {
        return this.f7147f;
    }

    @Override // B2.E
    public long r() {
        return this.f7144c.r();
    }

    @Override // B2.E
    public x v() {
        return this.f7144c.v();
    }

    @Override // B2.E
    public Q2.k y() {
        if (this.f7146e == null) {
            this.f7146e = t.d(d0(this.f7144c.y()));
        }
        return this.f7146e;
    }
}
