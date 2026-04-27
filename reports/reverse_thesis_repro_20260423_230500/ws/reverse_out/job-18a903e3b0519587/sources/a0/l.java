package a0;

import java.io.InputStream;
import java.io.OutputStream;

/* JADX INFO: loaded from: classes.dex */
public class l {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2926a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0215a f2927b;

    public l(InterfaceC0215a interfaceC0215a) {
        this(interfaceC0215a, 16384);
    }

    public long a(InputStream inputStream, OutputStream outputStream) {
        byte[] bArr = (byte[]) this.f2927b.get(this.f2926a);
        long j3 = 0;
        while (true) {
            try {
                int i3 = inputStream.read(bArr, 0, this.f2926a);
                if (i3 == -1) {
                    return j3;
                }
                outputStream.write(bArr, 0, i3);
                j3 += (long) i3;
            } finally {
                this.f2927b.a(bArr);
            }
        }
    }

    public l(InterfaceC0215a interfaceC0215a, int i3) {
        X.k.b(Boolean.valueOf(i3 > 0));
        this.f2926a = i3;
        this.f2927b = interfaceC0215a;
    }
}
