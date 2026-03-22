package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/* renamed from: b.l.a.a.o1.d0 */
/* loaded from: classes.dex */
public final class C2287d0 implements InterfaceC2321m {

    /* renamed from: a */
    public final InterfaceC2321m f5796a;

    /* renamed from: b */
    public long f5797b;

    /* renamed from: c */
    public Uri f5798c;

    /* renamed from: d */
    public Map<String, List<String>> f5799d;

    public C2287d0(InterfaceC2321m interfaceC2321m) {
        Objects.requireNonNull(interfaceC2321m);
        this.f5796a = interfaceC2321m;
        this.f5798c = Uri.EMPTY;
        this.f5799d = Collections.emptyMap();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void addTransferListener(InterfaceC2291f0 interfaceC2291f0) {
        this.f5796a.addTransferListener(interfaceC2291f0);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        this.f5796a.close();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public Map<String, List<String>> getResponseHeaders() {
        return this.f5796a.getResponseHeaders();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f5796a.getUri();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        this.f5798c = c2324p.f5933a;
        this.f5799d = Collections.emptyMap();
        long open = this.f5796a.open(c2324p);
        Uri uri = getUri();
        Objects.requireNonNull(uri);
        this.f5798c = uri;
        this.f5799d = getResponseHeaders();
        return open;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        int read = this.f5796a.read(bArr, i2, i3);
        if (read != -1) {
            this.f5797b += read;
        }
        return read;
    }
}
