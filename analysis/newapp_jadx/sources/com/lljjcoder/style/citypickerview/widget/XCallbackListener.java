package com.lljjcoder.style.citypickerview.widget;

/* loaded from: classes2.dex */
public abstract class XCallbackListener {
    public void call(Object... objArr) {
        callback(objArr);
    }

    public abstract void callback(Object... objArr);
}
