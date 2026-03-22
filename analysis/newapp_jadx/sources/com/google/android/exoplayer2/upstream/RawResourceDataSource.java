package com.google.android.exoplayer2.upstream;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.content.res.Resources;
import android.net.Uri;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p248o1.AbstractC2294h;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class RawResourceDataSource extends AbstractC2294h {

    /* renamed from: a */
    public final Resources f9738a;

    /* renamed from: b */
    @Nullable
    public Uri f9739b;

    /* renamed from: c */
    @Nullable
    public AssetFileDescriptor f9740c;

    /* renamed from: d */
    @Nullable
    public InputStream f9741d;

    /* renamed from: e */
    public long f9742e;

    /* renamed from: f */
    public boolean f9743f;

    /* renamed from: com.google.android.exoplayer2.upstream.RawResourceDataSource$a */
    public static class C3325a extends IOException {
        public C3325a(String str) {
            super(str);
        }

        public C3325a(IOException iOException) {
            super(iOException);
        }
    }

    public RawResourceDataSource(Context context) {
        super(false);
        this.f9738a = context.getResources();
    }

    public static Uri buildRawResourceUri(int i2) {
        return Uri.parse("rawresource:///" + i2);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        this.f9739b = null;
        try {
            try {
                InputStream inputStream = this.f9741d;
                if (inputStream != null) {
                    inputStream.close();
                }
                this.f9741d = null;
                try {
                    try {
                        AssetFileDescriptor assetFileDescriptor = this.f9740c;
                        if (assetFileDescriptor != null) {
                            assetFileDescriptor.close();
                        }
                    } finally {
                        this.f9740c = null;
                        if (this.f9743f) {
                            this.f9743f = false;
                            transferEnded();
                        }
                    }
                } catch (IOException e2) {
                    throw new C3325a(e2);
                }
            } catch (IOException e3) {
                throw new C3325a(e3);
            }
        } catch (Throwable th) {
            this.f9741d = null;
            try {
                try {
                    AssetFileDescriptor assetFileDescriptor2 = this.f9740c;
                    if (assetFileDescriptor2 != null) {
                        assetFileDescriptor2.close();
                    }
                    this.f9740c = null;
                    if (this.f9743f) {
                        this.f9743f = false;
                        transferEnded();
                    }
                    throw th;
                } catch (IOException e4) {
                    throw new C3325a(e4);
                }
            } finally {
                this.f9740c = null;
                if (this.f9743f) {
                    this.f9743f = false;
                    transferEnded();
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f9739b;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        try {
            Uri uri = c2324p.f5933a;
            this.f9739b = uri;
            if (!TextUtils.equals("rawresource", uri.getScheme())) {
                throw new C3325a("URI must use scheme rawresource");
            }
            try {
                String lastPathSegment = uri.getLastPathSegment();
                Objects.requireNonNull(lastPathSegment);
                int parseInt = Integer.parseInt(lastPathSegment);
                transferInitializing(c2324p);
                AssetFileDescriptor openRawResourceFd = this.f9738a.openRawResourceFd(parseInt);
                this.f9740c = openRawResourceFd;
                if (openRawResourceFd == null) {
                    throw new C3325a("Resource is compressed: " + uri);
                }
                FileInputStream fileInputStream = new FileInputStream(openRawResourceFd.getFileDescriptor());
                this.f9741d = fileInputStream;
                fileInputStream.skip(openRawResourceFd.getStartOffset());
                if (fileInputStream.skip(c2324p.f5938f) < c2324p.f5938f) {
                    throw new EOFException();
                }
                long j2 = c2324p.f5939g;
                long j3 = -1;
                if (j2 != -1) {
                    this.f9742e = j2;
                } else {
                    long length = openRawResourceFd.getLength();
                    if (length != -1) {
                        j3 = length - c2324p.f5938f;
                    }
                    this.f9742e = j3;
                }
                this.f9743f = true;
                transferStarted(c2324p);
                return this.f9742e;
            } catch (NumberFormatException unused) {
                throw new C3325a("Resource identifier must be an integer.");
            }
        } catch (IOException e2) {
            throw new C3325a(e2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        if (i3 == 0) {
            return 0;
        }
        long j2 = this.f9742e;
        if (j2 == 0) {
            return -1;
        }
        if (j2 != -1) {
            try {
                i3 = (int) Math.min(j2, i3);
            } catch (IOException e2) {
                throw new C3325a(e2);
            }
        }
        InputStream inputStream = this.f9741d;
        int i4 = C2344d0.f6035a;
        int read = inputStream.read(bArr, i2, i3);
        if (read == -1) {
            if (this.f9742e == -1) {
                return -1;
            }
            throw new C3325a(new EOFException());
        }
        long j3 = this.f9742e;
        if (j3 != -1) {
            this.f9742e = j3 - read;
        }
        bytesTransferred(read);
        return read;
    }
}
