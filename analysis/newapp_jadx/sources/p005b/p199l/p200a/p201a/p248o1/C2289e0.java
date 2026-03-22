package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/* renamed from: b.l.a.a.o1.e0 */
/* loaded from: classes.dex */
public final class C2289e0 implements InterfaceC2321m {

    /* renamed from: a */
    public final InterfaceC2321m f5800a;

    /* renamed from: b */
    public final InterfaceC2319k f5801b;

    /* renamed from: c */
    public boolean f5802c;

    /* renamed from: d */
    public long f5803d;

    public C2289e0(InterfaceC2321m interfaceC2321m, InterfaceC2319k interfaceC2319k) {
        Objects.requireNonNull(interfaceC2321m);
        this.f5800a = interfaceC2321m;
        this.f5801b = interfaceC2319k;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void addTransferListener(InterfaceC2291f0 interfaceC2291f0) {
        this.f5800a.addTransferListener(interfaceC2291f0);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        try {
            this.f5800a.close();
        } finally {
            if (this.f5802c) {
                this.f5802c = false;
                this.f5801b.close();
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public Map<String, List<String>> getResponseHeaders() {
        return this.f5800a.getResponseHeaders();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f5800a.getUri();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        long open = this.f5800a.open(c2324p);
        this.f5803d = open;
        if (open == 0) {
            return 0L;
        }
        if (c2324p.f5939g == -1 && open != -1) {
            c2324p = c2324p.m2269d(0L, open);
        }
        this.f5802c = true;
        this.f5801b.open(c2324p);
        return this.f5803d;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        if (this.f5803d == 0) {
            return -1;
        }
        int read = this.f5800a.read(bArr, i2, i3);
        if (read > 0) {
            this.f5801b.mo2215a(bArr, i2, read);
            long j2 = this.f5803d;
            if (j2 != -1) {
                this.f5803d = j2 - read;
            }
        }
        return read;
    }
}
