package io.openinstall.sdk;

import com.fm.openinstall.listener.ResultCallback;
import com.fm.openinstall.model.Error;

/* JADX INFO: loaded from: classes3.dex */
class d implements da {
    final /* synthetic */ ResultCallback a;
    final /* synthetic */ a b;

    d(a aVar, ResultCallback resultCallback) {
        this.b = aVar;
        this.a = resultCallback;
    }

    @Override // io.openinstall.sdk.da
    public void a(cy cyVar) {
        ResultCallback resultCallback = this.a;
        if (resultCallback != null) {
            resultCallback.onResult(null, Error.fromInner(cyVar.c()));
        }
    }
}
