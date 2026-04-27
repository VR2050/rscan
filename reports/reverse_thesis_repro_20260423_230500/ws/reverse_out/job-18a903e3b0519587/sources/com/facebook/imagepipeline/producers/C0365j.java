package com.facebook.imagepipeline.producers;

import android.graphics.Bitmap;
import b0.AbstractC0311a;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.j, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0365j implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6272a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f6273b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f6274c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f6275d;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.j$a */
    private static class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f6276c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int f6277d;

        a(InterfaceC0369n interfaceC0369n, int i3, int i4) {
            super(interfaceC0369n);
            this.f6276c = i3;
            this.f6277d = i4;
        }

        private void q(AbstractC0311a abstractC0311a) {
            N0.d dVar;
            Bitmap bitmapC;
            int rowBytes;
            if (abstractC0311a == null || !abstractC0311a.Z() || (dVar = (N0.d) abstractC0311a.P()) == null || dVar.a() || !(dVar instanceof N0.e) || (bitmapC = ((N0.e) dVar).C()) == null || (rowBytes = bitmapC.getRowBytes() * bitmapC.getHeight()) < this.f6276c || rowBytes > this.f6277d) {
                return;
            }
            bitmapC.prepareToDraw();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: r, reason: merged with bridge method [inline-methods] */
        public void i(AbstractC0311a abstractC0311a, int i3) {
            q(abstractC0311a);
            p().d(abstractC0311a, i3);
        }
    }

    public C0365j(d0 d0Var, int i3, int i4, boolean z3) {
        X.k.b(Boolean.valueOf(i3 <= i4));
        this.f6272a = (d0) X.k.g(d0Var);
        this.f6273b = i3;
        this.f6274c = i4;
        this.f6275d = z3;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        if (!e0Var.v() || this.f6275d) {
            this.f6272a.a(new a(interfaceC0369n, this.f6273b, this.f6274c), e0Var);
        } else {
            this.f6272a.a(interfaceC0369n, e0Var);
        }
    }
}
