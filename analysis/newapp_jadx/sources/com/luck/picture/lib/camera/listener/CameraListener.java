package com.luck.picture.lib.camera.listener;

import androidx.annotation.NonNull;
import java.io.File;

/* loaded from: classes2.dex */
public interface CameraListener {
    void onError(int i2, String str, Throwable th);

    void onPictureSuccess(@NonNull File file);

    void onRecordSuccess(@NonNull File file);
}
