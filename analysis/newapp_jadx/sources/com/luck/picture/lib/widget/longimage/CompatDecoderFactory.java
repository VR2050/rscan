package com.luck.picture.lib.widget.longimage;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class CompatDecoderFactory<T> implements DecoderFactory<T> {
    private Class<? extends T> clazz;

    public CompatDecoderFactory(@NonNull Class<? extends T> cls) {
        this.clazz = cls;
    }

    @Override // com.luck.picture.lib.widget.longimage.DecoderFactory
    public T make() {
        return this.clazz.newInstance();
    }
}
