package com.luck.picture.lib.compress;

import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes2.dex */
public abstract class InputStreamAdapter implements InputStreamProvider {
    private InputStream inputStream;

    @Override // com.luck.picture.lib.compress.InputStreamProvider
    public void close() {
        InputStream inputStream = this.inputStream;
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException unused) {
            } catch (Throwable th) {
                this.inputStream = null;
                throw th;
            }
            this.inputStream = null;
        }
    }

    @Override // com.luck.picture.lib.compress.InputStreamProvider
    public InputStream open() {
        close();
        InputStream openInternal = openInternal();
        this.inputStream = openInternal;
        return openInternal;
    }

    public abstract InputStream openInternal();
}
