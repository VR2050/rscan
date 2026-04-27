package com.facebook.imagepipeline.producers;

import T0.b;
import java.util.Map;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.u, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0375u {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0375u f6379a = new C0375u();

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.u$a */
    public static final class a extends Exception {
        public a(String str) {
            super(str);
        }
    }

    private C0375u() {
    }

    public static final G0.j a(T0.b bVar, G0.j jVar, G0.j jVar2, Map map) {
        String strF;
        t2.j.f(bVar, "imageRequest");
        if (bVar.c() == b.EnumC0041b.SMALL) {
            return jVar;
        }
        if (bVar.c() == b.EnumC0041b.DEFAULT) {
            return jVar2;
        }
        if (bVar.c() != b.EnumC0041b.DYNAMIC || map == null || (strF = bVar.f()) == null) {
            return null;
        }
        return (G0.j) map.get(strF);
    }
}
