package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.util.List;
import java.util.Map;

/* renamed from: b.l.a.a.o1.m */
/* loaded from: classes.dex */
public interface InterfaceC2321m {

    /* renamed from: b.l.a.a.o1.m$a */
    public interface a {
        InterfaceC2321m createDataSource();
    }

    void addTransferListener(InterfaceC2291f0 interfaceC2291f0);

    void close();

    Map<String, List<String>> getResponseHeaders();

    @Nullable
    Uri getUri();

    long open(C2324p c2324p);

    int read(byte[] bArr, int i2, int i3);
}
