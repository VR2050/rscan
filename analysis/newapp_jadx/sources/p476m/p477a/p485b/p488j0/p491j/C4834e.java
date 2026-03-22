package p476m.p477a.p485b.p488j0.p491j;

import java.io.IOException;
import java.io.InputStream;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4790a;
import p476m.p477a.p485b.p492k0.InterfaceC4847a;
import p476m.p477a.p485b.p492k0.InterfaceC4850d;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: m.a.b.j0.j.e */
/* loaded from: classes3.dex */
public class C4834e extends InputStream {

    /* renamed from: c */
    public final long f12390c;

    /* renamed from: e */
    public long f12391e = 0;

    /* renamed from: f */
    public boolean f12392f = false;

    /* renamed from: g */
    public InterfaceC4850d f12393g;

    public C4834e(InterfaceC4850d interfaceC4850d, long j2) {
        this.f12393g = null;
        C2354n.m2470e1(interfaceC4850d, "Session input buffer");
        this.f12393g = interfaceC4850d;
        C2354n.m2466d1(j2, "Content length");
        this.f12390c = j2;
    }

    @Override // java.io.InputStream
    public int available() {
        InterfaceC4850d interfaceC4850d = this.f12393g;
        if (interfaceC4850d instanceof InterfaceC4847a) {
            return Math.min(((InterfaceC4847a) interfaceC4850d).length(), (int) (this.f12390c - this.f12391e));
        }
        return 0;
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f12392f) {
            return;
        }
        try {
            if (this.f12391e < this.f12390c) {
                do {
                } while (read(new byte[2048]) >= 0);
            }
        } finally {
            this.f12392f = true;
        }
    }

    @Override // java.io.InputStream
    public int read() {
        if (this.f12392f) {
            throw new IOException("Attempted read from closed stream.");
        }
        if (this.f12391e >= this.f12390c) {
            return -1;
        }
        int read = this.f12393g.read();
        if (read != -1) {
            this.f12391e++;
        } else if (this.f12391e < this.f12390c) {
            throw new C4790a("Premature end of Content-Length delimited message body (expected: %,d; received: %,d)", Long.valueOf(this.f12390c), Long.valueOf(this.f12391e));
        }
        return read;
    }

    @Override // java.io.InputStream
    public long skip(long j2) {
        int read;
        if (j2 <= 0) {
            return 0L;
        }
        byte[] bArr = new byte[2048];
        long min = Math.min(j2, this.f12390c - this.f12391e);
        long j3 = 0;
        while (min > 0 && (read = read(bArr, 0, (int) Math.min(IjkMediaMeta.AV_CH_TOP_CENTER, min))) != -1) {
            long j4 = read;
            j3 += j4;
            min -= j4;
        }
        return j3;
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i2, int i3) {
        if (!this.f12392f) {
            long j2 = this.f12391e;
            long j3 = this.f12390c;
            if (j2 >= j3) {
                return -1;
            }
            if (i3 + j2 > j3) {
                i3 = (int) (j3 - j2);
            }
            int read = this.f12393g.read(bArr, i2, i3);
            if (read == -1 && this.f12391e < this.f12390c) {
                throw new C4790a("Premature end of Content-Length delimited message body (expected: %,d; received: %,d)", Long.valueOf(this.f12390c), Long.valueOf(this.f12391e));
            }
            if (read > 0) {
                this.f12391e += read;
            }
            return read;
        }
        throw new IOException("Attempted read from closed stream.");
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr) {
        return read(bArr, 0, bArr.length);
    }
}
