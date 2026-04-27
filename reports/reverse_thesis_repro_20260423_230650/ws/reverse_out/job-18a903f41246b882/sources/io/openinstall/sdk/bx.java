package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
class bx implements Runnable {
    final /* synthetic */ bv a;

    bx(bv bvVar) {
        this.a = bvVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        this.a.b("lifecycle");
    }
}
