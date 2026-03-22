package p476m.p477a.p478a.p483b.p484d;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p477a.p478a.p483b.C4785b;

/* renamed from: m.a.a.b.d.b */
/* loaded from: classes3.dex */
public class C4788b extends OutputStream {

    /* renamed from: c */
    public final int f12269c;

    /* renamed from: e */
    public long f12270e;

    /* renamed from: f */
    public boolean f12271f;

    /* renamed from: g */
    public C4787a f12272g;

    /* renamed from: h */
    public OutputStream f12273h;

    /* renamed from: i */
    public File f12274i;

    public C4788b(int i2, File file) {
        this.f12269c = i2;
        this.f12274i = file;
        C4787a c4787a = new C4787a(1024);
        this.f12272g = c4787a;
        this.f12273h = c4787a;
    }

    /* renamed from: b */
    public void m5467b(int i2) {
        if (this.f12271f || this.f12270e + i2 <= this.f12269c) {
            return;
        }
        this.f12271f = true;
        File file = this.f12274i;
        BigInteger bigInteger = C4785b.f12256a;
        File parentFile = file.getParentFile();
        if (parentFile != null) {
            if (parentFile.exists()) {
                if (!parentFile.isDirectory()) {
                    throw new IOException("File " + parentFile + " exists and is not a directory. Unable to create directory.");
                }
            } else if (!parentFile.mkdirs() && !parentFile.isDirectory()) {
                throw new IOException(C1499a.m634t("Unable to create directory ", parentFile));
            }
        }
        FileOutputStream fileOutputStream = new FileOutputStream(this.f12274i);
        try {
            C4787a c4787a = this.f12272g;
            synchronized (c4787a) {
                int i3 = c4787a.f12268i;
                for (byte[] bArr : c4787a.f12264e) {
                    int min = Math.min(bArr.length, i3);
                    fileOutputStream.write(bArr, 0, min);
                    i3 -= min;
                    if (i3 == 0) {
                        break;
                    }
                }
            }
            this.f12273h = fileOutputStream;
            this.f12272g = null;
        } catch (IOException e2) {
            fileOutputStream.close();
            throw e2;
        }
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        try {
            this.f12273h.flush();
        } catch (IOException unused) {
        }
        this.f12273h.close();
    }

    /* renamed from: d */
    public boolean m5468d() {
        return !(this.f12270e > ((long) this.f12269c));
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() {
        this.f12273h.flush();
    }

    @Override // java.io.OutputStream
    public void write(int i2) {
        m5467b(1);
        this.f12273h.write(i2);
        this.f12270e++;
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) {
        m5467b(bArr.length);
        this.f12273h.write(bArr);
        this.f12270e += bArr.length;
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i2, int i3) {
        m5467b(i3);
        this.f12273h.write(bArr, i2, i3);
        this.f12270e += i3;
    }
}
