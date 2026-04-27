package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
class ct implements Runnable {
    final /* synthetic */ cs a;

    ct(cs csVar) {
        this.a = csVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        System.currentTimeMillis();
        cy cyVarN = this.a.n();
        if (this.a.b != null) {
            this.a.a.b().post(new cu(this, cyVarN));
        }
        System.currentTimeMillis();
    }
}
