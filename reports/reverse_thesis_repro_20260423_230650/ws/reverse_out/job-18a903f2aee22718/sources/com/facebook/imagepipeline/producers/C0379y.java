package com.facebook.imagepipeline.producers;

import android.util.Pair;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.y, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0379y extends U {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final G0.k f6396f;

    public C0379y(G0.k kVar, boolean z3, d0 d0Var) {
        super(d0Var, "EncodedCacheKeyMultiplexProducer", "multiplex_enc_cnt", z3);
        this.f6396f = kVar;
    }

    @Override // com.facebook.imagepipeline.producers.U
    /* JADX INFO: renamed from: l, reason: merged with bridge method [inline-methods] */
    public N0.j g(N0.j jVar) {
        return N0.j.i(jVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.imagepipeline.producers.U
    /* JADX INFO: renamed from: m, reason: merged with bridge method [inline-methods] */
    public Pair j(e0 e0Var) {
        return Pair.create(this.f6396f.a(e0Var.W(), e0Var.i()), e0Var.e0());
    }
}
