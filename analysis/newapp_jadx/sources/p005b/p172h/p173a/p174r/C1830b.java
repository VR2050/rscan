package p005b.p172h.p173a.p174r;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import p005b.p172h.p173a.C1825n;
import p005b.p172h.p173a.InterfaceC1812a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.h.a.r.b */
/* loaded from: classes.dex */
public class C1830b implements InterfaceC1812a {

    /* renamed from: a */
    public final InterfaceC1829a f2833a;

    /* renamed from: b */
    public File f2834b;

    /* renamed from: c */
    public RandomAccessFile f2835c;

    public C1830b(File file, InterfaceC1829a interfaceC1829a) {
        File file2;
        try {
            if (interfaceC1829a == null) {
                throw new NullPointerException();
            }
            this.f2833a = interfaceC1829a;
            C4195m.m4839w0(file.getParentFile());
            boolean exists = file.exists();
            if (exists) {
                file2 = file;
            } else {
                file2 = new File(file.getParentFile(), file.getName() + ".download");
            }
            this.f2834b = file2;
            this.f2835c = new RandomAccessFile(this.f2834b, exists ? "r" : "rw");
        } catch (IOException e2) {
            throw new C1825n("Error using file " + file + " as disc cache", e2);
        }
    }

    @Override // p005b.p172h.p173a.InterfaceC1812a
    /* renamed from: a */
    public synchronized void mo1156a(byte[] bArr, int i2) {
        try {
            if (mo1157b()) {
                throw new C1825n("Error append cache: cache file " + this.f2834b + " is completed!");
            }
            this.f2835c.seek(available());
            this.f2835c.write(bArr, 0, i2);
        } catch (IOException e2) {
            throw new C1825n(String.format("Error writing %d bytes to %s from buffer with size %d", Integer.valueOf(i2), this.f2835c, Integer.valueOf(bArr.length)), e2);
        }
    }

    @Override // p005b.p172h.p173a.InterfaceC1812a
    public synchronized long available() {
        try {
        } catch (IOException e2) {
            throw new C1825n("Error reading length of file " + this.f2834b, e2);
        }
        return (int) this.f2835c.length();
    }

    @Override // p005b.p172h.p173a.InterfaceC1812a
    /* renamed from: b */
    public synchronized boolean mo1157b() {
        return !this.f2834b.getName().endsWith(".download");
    }

    @Override // p005b.p172h.p173a.InterfaceC1812a
    /* renamed from: c */
    public synchronized int mo1158c(byte[] bArr, long j2, int i2) {
        try {
            this.f2835c.seek(j2);
        } catch (IOException e2) {
            throw new C1825n(String.format("Error reading %d bytes with offset %d from file[%d bytes] to buffer[%d bytes]", Integer.valueOf(i2), Long.valueOf(j2), Long.valueOf(available()), Integer.valueOf(bArr.length)), e2);
        }
        return this.f2835c.read(bArr, 0, i2);
    }

    @Override // p005b.p172h.p173a.InterfaceC1812a
    public synchronized void close() {
        try {
            this.f2835c.close();
            ((AbstractC1833e) this.f2833a).m1188a(this.f2834b);
        } catch (IOException e2) {
            throw new C1825n("Error closing file " + this.f2834b, e2);
        }
    }

    @Override // p005b.p172h.p173a.InterfaceC1812a
    public synchronized void complete() {
        if (mo1157b()) {
            return;
        }
        close();
        File file = new File(this.f2834b.getParentFile(), this.f2834b.getName().substring(0, this.f2834b.getName().length() - 9));
        if (!this.f2834b.renameTo(file)) {
            throw new C1825n("Error renaming file " + this.f2834b + " to " + file + " for completion!");
        }
        this.f2834b = file;
        try {
            this.f2835c = new RandomAccessFile(this.f2834b, "r");
            ((AbstractC1833e) this.f2833a).m1188a(this.f2834b);
        } catch (IOException e2) {
            throw new C1825n("Error opening " + this.f2834b + " as disc cache", e2);
        }
    }
}
