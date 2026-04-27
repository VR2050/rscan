package com.bjz.comm.net.listener;

import io.reactivex.ObservableEmitter;

/* JADX INFO: loaded from: classes4.dex */
public interface GetHttpTokenCallBack {
    void requestToken(ObservableEmitter<String> observableEmitter);
}
