package com.bjz.comm.net.mvp.model;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponseNoData;
import io.reactivex.functions.Consumer;

/* JADX INFO: renamed from: com.bjz.comm.net.mvp.model.-$$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes4.dex */
public final /* synthetic */ class $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo implements Consumer {
    private final /* synthetic */ DataListener f$0;

    @Override // io.reactivex.functions.Consumer
    public final void accept(Object obj) {
        this.f$0.onResponse((BResponseNoData) obj);
    }
}
