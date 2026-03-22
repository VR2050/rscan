package p476m.p477a.p478a.p483b.p484d;

import java.io.Serializable;
import java.io.Writer;

/* renamed from: m.a.a.b.d.c */
/* loaded from: classes3.dex */
public class C4789c extends Writer implements Serializable {
    private static final long serialVersionUID = -146927496096066153L;

    /* renamed from: c */
    public final StringBuilder f12275c;

    public C4789c(int i2) {
        this.f12275c = new StringBuilder(i2);
    }

    @Override // java.io.Writer, java.lang.Appendable
    public Writer append(char c2) {
        this.f12275c.append(c2);
        return this;
    }

    @Override // java.io.Writer, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    @Override // java.io.Writer, java.io.Flushable
    public void flush() {
    }

    public String toString() {
        return this.f12275c.toString();
    }

    @Override // java.io.Writer
    public void write(String str) {
        if (str != null) {
            this.f12275c.append(str);
        }
    }

    @Override // java.io.Writer, java.lang.Appendable
    public Appendable append(char c2) {
        this.f12275c.append(c2);
        return this;
    }

    @Override // java.io.Writer
    public void write(char[] cArr, int i2, int i3) {
        if (cArr != null) {
            this.f12275c.append(cArr, i2, i3);
        }
    }

    @Override // java.io.Writer, java.lang.Appendable
    public Writer append(CharSequence charSequence) {
        this.f12275c.append(charSequence);
        return this;
    }

    @Override // java.io.Writer, java.lang.Appendable
    public Appendable append(CharSequence charSequence) {
        this.f12275c.append(charSequence);
        return this;
    }

    @Override // java.io.Writer, java.lang.Appendable
    public Writer append(CharSequence charSequence, int i2, int i3) {
        this.f12275c.append(charSequence, i2, i3);
        return this;
    }

    @Override // java.io.Writer, java.lang.Appendable
    public Appendable append(CharSequence charSequence, int i2, int i3) {
        this.f12275c.append(charSequence, i2, i3);
        return this;
    }
}
