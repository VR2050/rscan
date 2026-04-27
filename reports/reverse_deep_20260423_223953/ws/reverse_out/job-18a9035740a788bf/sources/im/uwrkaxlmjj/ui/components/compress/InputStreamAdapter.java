package im.uwrkaxlmjj.ui.components.compress;

import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes5.dex */
public abstract class InputStreamAdapter implements InputStreamProvider {
    private InputStream inputStream;

    public abstract InputStream openInternal() throws IOException;

    @Override // im.uwrkaxlmjj.ui.components.compress.InputStreamProvider
    public InputStream open() throws IOException {
        close();
        InputStream inputStreamOpenInternal = openInternal();
        this.inputStream = inputStreamOpenInternal;
        return inputStreamOpenInternal;
    }

    @Override // im.uwrkaxlmjj.ui.components.compress.InputStreamProvider
    public void close() {
        InputStream inputStream = this.inputStream;
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException e) {
            } catch (Throwable th) {
                this.inputStream = null;
                throw th;
            }
            this.inputStream = null;
        }
    }
}
