package p476m.p477a.p478a.p483b;

import java.io.EOFException;
import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p477a.p478a.p483b.p484d.C4789c;

/* renamed from: m.a.a.b.c */
/* loaded from: classes3.dex */
public class C4786c {

    /* renamed from: a */
    public static final /* synthetic */ int f12262a = 0;

    static {
        char c2 = File.separatorChar;
        C4789c c4789c = new C4789c(4);
        try {
            PrintWriter printWriter = new PrintWriter(c4789c);
            try {
                printWriter.println();
                c4789c.toString();
                printWriter.close();
            } finally {
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    /* renamed from: a */
    public static void m5464a(InputStream inputStream, byte[] bArr) {
        int length = bArr.length;
        if (length < 0) {
            throw new IllegalArgumentException(C1499a.m626l("Length must not be negative: ", length));
        }
        int i2 = length;
        while (i2 > 0) {
            int read = inputStream.read(bArr, (length - i2) + 0, i2);
            if (-1 == read) {
                break;
            } else {
                i2 -= read;
            }
        }
        int i3 = length - i2;
        if (i3 != length) {
            throw new EOFException(C1499a.m629o("Length to read: ", length, " actual: ", i3));
        }
    }
}
