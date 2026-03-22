package p005b.p199l.p200a.p201a.p250p1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.a.a.p1.e */
/* loaded from: classes.dex */
public final class C2345e {

    /* renamed from: a */
    public final File f6049a;

    /* renamed from: b */
    public final File f6050b;

    /* renamed from: b.l.a.a.p1.e$a */
    public static final class a extends OutputStream {

        /* renamed from: c */
        public final FileOutputStream f6051c;

        /* renamed from: e */
        public boolean f6052e = false;

        public a(File file) {
            this.f6051c = new FileOutputStream(file);
        }

        @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (this.f6052e) {
                return;
            }
            this.f6052e = true;
            this.f6051c.flush();
            try {
                this.f6051c.getFD().sync();
            } catch (IOException unused) {
            }
            this.f6051c.close();
        }

        @Override // java.io.OutputStream, java.io.Flushable
        public void flush() {
            this.f6051c.flush();
        }

        @Override // java.io.OutputStream
        public void write(int i2) {
            this.f6051c.write(i2);
        }

        @Override // java.io.OutputStream
        public void write(byte[] bArr) {
            this.f6051c.write(bArr);
        }

        @Override // java.io.OutputStream
        public void write(byte[] bArr, int i2, int i3) {
            this.f6051c.write(bArr, i2, i3);
        }
    }

    public C2345e(File file) {
        this.f6049a = file;
        this.f6050b = new File(file.getPath() + ".bak");
    }

    /* renamed from: a */
    public boolean m2349a() {
        return this.f6049a.exists() || this.f6050b.exists();
    }

    /* renamed from: b */
    public InputStream m2350b() {
        if (this.f6050b.exists()) {
            this.f6049a.delete();
            this.f6050b.renameTo(this.f6049a);
        }
        return new FileInputStream(this.f6049a);
    }

    /* renamed from: c */
    public OutputStream m2351c() {
        if (this.f6049a.exists()) {
            if (this.f6050b.exists()) {
                this.f6049a.delete();
            } else if (!this.f6049a.renameTo(this.f6050b)) {
                StringBuilder m586H = C1499a.m586H("Couldn't rename file ");
                m586H.append(this.f6049a);
                m586H.append(" to backup file ");
                m586H.append(this.f6050b);
                m586H.toString();
            }
        }
        try {
            return new a(this.f6049a);
        } catch (FileNotFoundException e2) {
            File parentFile = this.f6049a.getParentFile();
            if (parentFile == null || !parentFile.mkdirs()) {
                StringBuilder m586H2 = C1499a.m586H("Couldn't create ");
                m586H2.append(this.f6049a);
                throw new IOException(m586H2.toString(), e2);
            }
            try {
                return new a(this.f6049a);
            } catch (FileNotFoundException e3) {
                StringBuilder m586H3 = C1499a.m586H("Couldn't create ");
                m586H3.append(this.f6049a);
                throw new IOException(m586H3.toString(), e3);
            }
        }
    }
}
