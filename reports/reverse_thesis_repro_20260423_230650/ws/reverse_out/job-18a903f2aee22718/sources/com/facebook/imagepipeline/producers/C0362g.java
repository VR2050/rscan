package com.facebook.imagepipeline.producers;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0362g extends C0364i {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f6262d = new a(null);

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.g$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0362g(G0.x xVar, G0.k kVar, d0 d0Var) {
        super(xVar, kVar, d0Var);
        t2.j.f(xVar, "memoryCache");
        t2.j.f(kVar, "cacheKeyFactory");
        t2.j.f(d0Var, "inputProducer");
    }

    @Override // com.facebook.imagepipeline.producers.C0364i
    protected String d() {
        return "pipe_ui";
    }

    @Override // com.facebook.imagepipeline.producers.C0364i
    protected String e() {
        return "BitmapMemoryCacheGetProducer";
    }

    @Override // com.facebook.imagepipeline.producers.C0364i
    protected InterfaceC0369n g(InterfaceC0369n interfaceC0369n, R.d dVar, boolean z3) {
        t2.j.f(interfaceC0369n, "consumer");
        t2.j.f(dVar, "cacheKey");
        return interfaceC0369n;
    }
}
