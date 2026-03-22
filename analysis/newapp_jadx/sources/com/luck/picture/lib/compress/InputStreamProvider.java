package com.luck.picture.lib.compress;

import com.luck.picture.lib.entity.LocalMedia;
import java.io.InputStream;

/* loaded from: classes2.dex */
public interface InputStreamProvider {
    void close();

    LocalMedia getMedia();

    String getPath();

    InputStream open();
}
