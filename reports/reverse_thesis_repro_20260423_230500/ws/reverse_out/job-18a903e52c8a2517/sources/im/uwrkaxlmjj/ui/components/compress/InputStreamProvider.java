package im.uwrkaxlmjj.ui.components.compress;

import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes5.dex */
public interface InputStreamProvider {
    void close();

    String getPath();

    InputStream open() throws IOException;
}
