package io.openinstall.sdk;

import com.fm.openinstall.listener.ResultCallback;
import com.fm.openinstall.model.Error;
import java.io.File;

/* JADX INFO: loaded from: classes3.dex */
class e implements da {
    final /* synthetic */ ResultCallback a;
    final /* synthetic */ a b;

    e(a aVar, ResultCallback resultCallback) {
        this.b = aVar;
        this.a = resultCallback;
    }

    @Override // io.openinstall.sdk.da
    public void a(cy cyVar) {
        ResultCallback resultCallback = this.a;
        if (resultCallback != null) {
            resultCallback.onResult(new File(cyVar.b()), Error.fromInner(cyVar.c()));
        }
    }
}
