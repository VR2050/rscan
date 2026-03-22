package p005b.p199l.p200a.p201a.p248o1;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import androidx.annotation.Nullable;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.channels.FileChannel;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.o1.i */
/* loaded from: classes.dex */
public final class C2317i extends AbstractC2294h {

    /* renamed from: a */
    public final ContentResolver f5916a;

    /* renamed from: b */
    @Nullable
    public Uri f5917b;

    /* renamed from: c */
    @Nullable
    public AssetFileDescriptor f5918c;

    /* renamed from: d */
    @Nullable
    public FileInputStream f5919d;

    /* renamed from: e */
    public long f5920e;

    /* renamed from: f */
    public boolean f5921f;

    /* renamed from: b.l.a.a.o1.i$a */
    public static class a extends IOException {
        public a(IOException iOException) {
            super(iOException);
        }
    }

    public C2317i(Context context) {
        super(false);
        this.f5916a = context.getContentResolver();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        this.f5917b = null;
        try {
            try {
                FileInputStream fileInputStream = this.f5919d;
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
                this.f5919d = null;
                try {
                    try {
                        AssetFileDescriptor assetFileDescriptor = this.f5918c;
                        if (assetFileDescriptor != null) {
                            assetFileDescriptor.close();
                        }
                    } finally {
                        this.f5918c = null;
                        if (this.f5921f) {
                            this.f5921f = false;
                            transferEnded();
                        }
                    }
                } catch (IOException e2) {
                    throw new a(e2);
                }
            } catch (IOException e3) {
                throw new a(e3);
            }
        } catch (Throwable th) {
            this.f5919d = null;
            try {
                try {
                    AssetFileDescriptor assetFileDescriptor2 = this.f5918c;
                    if (assetFileDescriptor2 != null) {
                        assetFileDescriptor2.close();
                    }
                    this.f5918c = null;
                    if (this.f5921f) {
                        this.f5921f = false;
                        transferEnded();
                    }
                    throw th;
                } catch (IOException e4) {
                    throw new a(e4);
                }
            } finally {
                this.f5918c = null;
                if (this.f5921f) {
                    this.f5921f = false;
                    transferEnded();
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f5917b;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        try {
            Uri uri = c2324p.f5933a;
            this.f5917b = uri;
            transferInitializing(c2324p);
            AssetFileDescriptor openAssetFileDescriptor = this.f5916a.openAssetFileDescriptor(uri, "r");
            this.f5918c = openAssetFileDescriptor;
            if (openAssetFileDescriptor == null) {
                throw new FileNotFoundException("Could not open file descriptor for: " + uri);
            }
            FileInputStream fileInputStream = new FileInputStream(openAssetFileDescriptor.getFileDescriptor());
            this.f5919d = fileInputStream;
            long startOffset = openAssetFileDescriptor.getStartOffset();
            long skip = fileInputStream.skip(c2324p.f5938f + startOffset) - startOffset;
            if (skip != c2324p.f5938f) {
                throw new EOFException();
            }
            long j2 = c2324p.f5939g;
            long j3 = -1;
            if (j2 != -1) {
                this.f5920e = j2;
            } else {
                long length = openAssetFileDescriptor.getLength();
                if (length == -1) {
                    FileChannel channel = fileInputStream.getChannel();
                    long size = channel.size();
                    if (size != 0) {
                        j3 = size - channel.position();
                    }
                    this.f5920e = j3;
                } else {
                    this.f5920e = length - skip;
                }
            }
            this.f5921f = true;
            transferStarted(c2324p);
            return this.f5920e;
        } catch (IOException e2) {
            throw new a(e2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        if (i3 == 0) {
            return 0;
        }
        long j2 = this.f5920e;
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
        FileInputStream fileInputStream = this.f5919d;
        int i4 = C2344d0.f6035a;
        int read = fileInputStream.read(bArr, i2, i3);
        if (read == -1) {
            if (this.f5920e == -1) {
                return -1;
            }
            throw new a(new EOFException());
        }
        long j3 = this.f5920e;
        if (j3 != -1) {
            this.f5920e = j3 - read;
        }
        bytesTransferred(read);
        return read;
    }
}
