package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.o1.x */
/* loaded from: classes.dex */
public final class C2332x extends AbstractC2294h {

    /* renamed from: a */
    @Nullable
    public RandomAccessFile f6012a;

    /* renamed from: b */
    @Nullable
    public Uri f6013b;

    /* renamed from: c */
    public long f6014c;

    /* renamed from: d */
    public boolean f6015d;

    /* renamed from: b.l.a.a.o1.x$a */
    public static final class a implements InterfaceC2321m.a {
        @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m.a
        public InterfaceC2321m createDataSource() {
            return new C2332x();
        }
    }

    /* renamed from: b.l.a.a.o1.x$b */
    public static class b extends IOException {
        public b(IOException iOException) {
            super(iOException);
        }

        public b(String str, IOException iOException) {
            super(str, iOException);
        }
    }

    public C2332x() {
        super(false);
    }

    /* renamed from: a */
    public static RandomAccessFile m2282a(Uri uri) {
        try {
            String path = uri.getPath();
            Objects.requireNonNull(path);
            return new RandomAccessFile(path, "r");
        } catch (FileNotFoundException e2) {
            if (TextUtils.isEmpty(uri.getQuery()) && TextUtils.isEmpty(uri.getFragment())) {
                throw new b(e2);
            }
            throw new b(String.format("uri has query and/or fragment, which are not supported. Did you call Uri.parse() on a string containing '?' or '#'? Use Uri.fromFile(new File(path)) to avoid this. path=%s,query=%s,fragment=%s", uri.getPath(), uri.getQuery(), uri.getFragment()), e2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        this.f6013b = null;
        try {
            try {
                RandomAccessFile randomAccessFile = this.f6012a;
                if (randomAccessFile != null) {
                    randomAccessFile.close();
                }
            } catch (IOException e2) {
                throw new b(e2);
            }
        } finally {
            this.f6012a = null;
            if (this.f6015d) {
                this.f6015d = false;
                transferEnded();
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f6013b;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        try {
            Uri uri = c2324p.f5933a;
            this.f6013b = uri;
            transferInitializing(c2324p);
            RandomAccessFile m2282a = m2282a(uri);
            this.f6012a = m2282a;
            m2282a.seek(c2324p.f5938f);
            long j2 = c2324p.f5939g;
            if (j2 == -1) {
                j2 = this.f6012a.length() - c2324p.f5938f;
            }
            this.f6014c = j2;
            if (j2 < 0) {
                throw new EOFException();
            }
            this.f6015d = true;
            transferStarted(c2324p);
            return this.f6014c;
        } catch (IOException e2) {
            throw new b(e2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        if (i3 == 0) {
            return 0;
        }
        long j2 = this.f6014c;
        if (j2 == 0) {
            return -1;
        }
        try {
            RandomAccessFile randomAccessFile = this.f6012a;
            int i4 = C2344d0.f6035a;
            int read = randomAccessFile.read(bArr, i2, (int) Math.min(j2, i3));
            if (read > 0) {
                this.f6014c -= read;
                bytesTransferred(read);
            }
            return read;
        } catch (IOException e2) {
            throw new b(e2);
        }
    }
}
