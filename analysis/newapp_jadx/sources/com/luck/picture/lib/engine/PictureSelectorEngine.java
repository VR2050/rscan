package com.luck.picture.lib.engine;

import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnResultCallbackListener;

/* loaded from: classes2.dex */
public interface PictureSelectorEngine {
    ImageEngine createEngine();

    OnResultCallbackListener<LocalMedia> getResultCallbackListener();
}
