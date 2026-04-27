package com.facebook.imagepipeline.producers;

/* JADX INFO: loaded from: classes.dex */
public final class F extends E implements P0.d {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final P0.e f6115c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final P0.d f6116d;

    public F(P0.e eVar, P0.d dVar) {
        super(eVar, dVar);
        this.f6115c = eVar;
        this.f6116d = dVar;
    }

    @Override // P0.d
    public void a(e0 e0Var) {
        t2.j.f(e0Var, "producerContext");
        P0.e eVar = this.f6115c;
        if (eVar != null) {
            eVar.j(e0Var.getId());
        }
        P0.d dVar = this.f6116d;
        if (dVar != null) {
            dVar.a(e0Var);
        }
    }

    @Override // P0.d
    public void c(e0 e0Var) {
        t2.j.f(e0Var, "producerContext");
        P0.e eVar = this.f6115c;
        if (eVar != null) {
            eVar.b(e0Var.W(), e0Var.i(), e0Var.getId(), e0Var.v());
        }
        P0.d dVar = this.f6116d;
        if (dVar != null) {
            dVar.c(e0Var);
        }
    }

    @Override // P0.d
    public void h(e0 e0Var) {
        t2.j.f(e0Var, "producerContext");
        P0.e eVar = this.f6115c;
        if (eVar != null) {
            eVar.d(e0Var.W(), e0Var.getId(), e0Var.v());
        }
        P0.d dVar = this.f6116d;
        if (dVar != null) {
            dVar.h(e0Var);
        }
    }

    @Override // P0.d
    public void k(e0 e0Var, Throwable th) {
        t2.j.f(e0Var, "producerContext");
        P0.e eVar = this.f6115c;
        if (eVar != null) {
            eVar.a(e0Var.W(), e0Var.getId(), th, e0Var.v());
        }
        P0.d dVar = this.f6116d;
        if (dVar != null) {
            dVar.k(e0Var, th);
        }
    }
}
