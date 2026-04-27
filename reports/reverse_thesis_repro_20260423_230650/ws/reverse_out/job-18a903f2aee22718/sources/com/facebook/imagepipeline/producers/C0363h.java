package com.facebook.imagepipeline.producers;

import android.util.Pair;
import b0.AbstractC0311a;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0363h extends U {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final G0.k f6263f;

    public C0363h(G0.k kVar, d0 d0Var) {
        super(d0Var, "BitmapMemoryCacheKeyMultiplexProducer", "multiplex_bmp_cnt");
        this.f6263f = kVar;
    }

    @Override // com.facebook.imagepipeline.producers.U
    /* JADX INFO: renamed from: l, reason: merged with bridge method [inline-methods] */
    public AbstractC0311a g(AbstractC0311a abstractC0311a) {
        return AbstractC0311a.A(abstractC0311a);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.imagepipeline.producers.U
    /* JADX INFO: renamed from: m, reason: merged with bridge method [inline-methods] */
    public Pair j(e0 e0Var) {
        return Pair.create(this.f6263f.c(e0Var.W(), e0Var.i()), e0Var.e0());
    }
}
