package im.uwrkaxlmjj.ui.components.compress;

import java.io.File;

/* JADX INFO: loaded from: classes5.dex */
public interface OnCompressListener {
    void onError(Throwable th);

    void onStart();

    void onSuccess(File file);
}
