package com.luck.picture.lib.listener;

import java.util.List;

/* loaded from: classes2.dex */
public interface OnResultCallbackListener<T> {
    void onCancel();

    void onResult(List<T> list);
}
