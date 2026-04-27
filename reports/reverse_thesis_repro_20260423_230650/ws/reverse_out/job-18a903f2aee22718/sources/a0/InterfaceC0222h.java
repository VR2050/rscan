package a0;

import java.io.Closeable;

/* JADX INFO: renamed from: a0.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public interface InterfaceC0222h extends Closeable {

    /* JADX INFO: renamed from: a0.h$a */
    public static class a extends RuntimeException {
        public a() {
            super("Invalid bytebuf. Already closed");
        }
    }

    boolean a();

    int c(int i3, byte[] bArr, int i4, int i5);

    byte g(int i3);

    int size();
}
