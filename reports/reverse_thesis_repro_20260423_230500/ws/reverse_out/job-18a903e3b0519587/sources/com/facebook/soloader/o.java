package com.facebook.soloader;

import a2.AbstractC0226b;

/* JADX INFO: loaded from: classes.dex */
public class o implements x {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final x f8378a;

    public o(x xVar) {
        this.f8378a = xVar;
    }

    @Override // com.facebook.soloader.x
    public void a(String str, int i3) {
        AbstractC0226b.j(this.f8378a, "load", i3);
        try {
            this.f8378a.a(str, i3);
            AbstractC0226b.i(null);
        } finally {
        }
    }
}
