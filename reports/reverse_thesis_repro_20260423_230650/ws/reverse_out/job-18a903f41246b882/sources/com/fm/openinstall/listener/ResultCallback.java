package com.fm.openinstall.listener;

import com.fm.openinstall.model.Error;

/* JADX INFO: loaded from: classes.dex */
public interface ResultCallback<Result> {
    void onResult(Result result, Error error);
}
