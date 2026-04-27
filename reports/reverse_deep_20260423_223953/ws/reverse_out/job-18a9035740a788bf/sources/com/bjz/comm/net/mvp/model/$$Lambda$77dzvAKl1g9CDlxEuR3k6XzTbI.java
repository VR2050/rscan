package com.bjz.comm.net.mvp.model;

import com.bjz.comm.net.base.DataListener;
import io.reactivex.functions.Consumer;

/* JADX INFO: renamed from: com.bjz.comm.net.mvp.model.-$$Lambda$77dzvAKl1g9CDlxE-uR3k6XzTbI, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes4.dex */
public final /* synthetic */ class $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI implements Consumer {
    private final /* synthetic */ DataListener f$0;

    @Override // io.reactivex.functions.Consumer
    public final void accept(Object obj) {
        this.f$0.onError((Throwable) obj);
    }
}
