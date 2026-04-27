package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
class bg implements Runnable {
    final /* synthetic */ bf a;

    bg(bf bfVar) {
        this.a = bfVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (this.a.c && this.a.d) {
            this.a.c = false;
            this.a.b();
        }
    }
}
