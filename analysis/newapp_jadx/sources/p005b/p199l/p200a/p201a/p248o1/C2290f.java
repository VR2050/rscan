package p005b.p199l.p200a.p201a.p248o1;

import android.content.Context;
import android.content.res.AssetManager;
import android.net.Uri;
import androidx.annotation.Nullable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.o1.f */
/* loaded from: classes.dex */
public final class C2290f extends AbstractC2294h {

    /* renamed from: a */
    public final AssetManager f5804a;

    /* renamed from: b */
    @Nullable
    public Uri f5805b;

    /* renamed from: c */
    @Nullable
    public InputStream f5806c;

    /* renamed from: d */
    public long f5807d;

    /* renamed from: e */
    public boolean f5808e;

    /* renamed from: b.l.a.a.o1.f$a */
    public static final class a extends IOException {
        public a(IOException iOException) {
            super(iOException);
        }
    }

    public C2290f(Context context) {
        super(false);
        this.f5804a = context.getAssets();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        this.f5805b = null;
        try {
            try {
                InputStream inputStream = this.f5806c;
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e2) {
                throw new a(e2);
            }
        } finally {
            this.f5806c = null;
            if (this.f5808e) {
                this.f5808e = false;
                transferEnded();
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f5805b;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        try {
            Uri uri = c2324p.f5933a;
            this.f5805b = uri;
            String path = uri.getPath();
            Objects.requireNonNull(path);
            if (path.startsWith("/android_asset/")) {
                path = path.substring(15);
            } else if (path.startsWith("/")) {
                path = path.substring(1);
            }
            transferInitializing(c2324p);
            InputStream open = this.f5804a.open(path, 1);
            this.f5806c = open;
            if (open.skip(c2324p.f5938f) < c2324p.f5938f) {
                throw new EOFException();
            }
            long j2 = c2324p.f5939g;
            if (j2 != -1) {
                this.f5807d = j2;
            } else {
                long available = this.f5806c.available();
                this.f5807d = available;
                if (available == 2147483647L) {
                    this.f5807d = -1L;
                }
            }
            this.f5808e = true;
            transferStarted(c2324p);
            return this.f5807d;
        } catch (IOException e2) {
            throw new a(e2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        if (i3 == 0) {
            return 0;
        }
        long j2 = this.f5807d;
        if (j2 == 0) {
            return -1;
        }
        if (j2 != -1) {
            try {
                i3 = (int) Math.min(j2, i3);
            } catch (IOException e2) {
                throw new a(e2);
            }
        }
        InputStream inputStream = this.f5806c;
        int i4 = C2344d0.f6035a;
        int read = inputStream.read(bArr, i2, i3);
        if (read == -1) {
            if (this.f5807d == -1) {
                return -1;
            }
            throw new a(new EOFException());
        }
        long j3 = this.f5807d;
        if (j3 != -1) {
            this.f5807d = j3 - read;
        }
        bytesTransferred(read);
        return read;
    }
}
