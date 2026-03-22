package androidx.camera.core.impl;

import androidx.annotation.NonNull;
import androidx.camera.core.ImageProxy;
import java.util.List;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public interface ImageProxyBundle {
    @NonNull
    List<Integer> getCaptureIds();

    @NonNull
    InterfaceFutureC2413a<ImageProxy> getImageProxy(int i2);
}
