package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
class cu implements Runnable {
    final /* synthetic */ cy a;
    final /* synthetic */ ct b;

    cu(ct ctVar, cy cyVar) {
        this.b = ctVar;
        this.a = cyVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        this.b.a.b.a(this.a);
    }
}
