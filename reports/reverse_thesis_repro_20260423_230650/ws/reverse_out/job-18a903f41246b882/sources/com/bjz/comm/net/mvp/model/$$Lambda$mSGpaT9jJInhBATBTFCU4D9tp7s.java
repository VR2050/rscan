package com.bjz.comm.net.mvp.model;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import io.reactivex.functions.Consumer;

/* JADX INFO: renamed from: com.bjz.comm.net.mvp.model.-$$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes4.dex */
public final /* synthetic */ class $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s implements Consumer {
    private final /* synthetic */ DataListener f$0;

    @Override // io.reactivex.functions.Consumer
    public final void accept(Object obj) {
        this.f$0.onResponse((BResponse) obj);
    }
}
