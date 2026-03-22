package androidx.camera.core;

import android.media.ImageReader;
import androidx.annotation.NonNull;
import androidx.camera.core.impl.ImageReaderProxy;

/* loaded from: classes.dex */
public final class ImageReaderProxys {
    private ImageReaderProxys() {
    }

    @NonNull
    public static ImageReaderProxy createIsolatedReader(int i2, int i3, int i4, int i5) {
        return new AndroidImageReaderProxy(ImageReader.newInstance(i2, i3, i4, i5));
    }
}
