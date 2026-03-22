package p005b.p113c0.p114a.p130l;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

/* renamed from: b.c0.a.l.d */
/* loaded from: classes2.dex */
public class C1492d {
    /* renamed from: a */
    public static boolean m562a(File file) {
        if (file == null || !file.exists()) {
            return true;
        }
        if (file.isFile()) {
            file.delete();
            return true;
        }
        if (!file.isDirectory()) {
            return true;
        }
        File[] listFiles = file.listFiles();
        if (listFiles != null) {
            for (File file2 : listFiles) {
                m562a(file2);
            }
        }
        file.delete();
        return true;
    }

    /* renamed from: b */
    public static void m563b(InputStream inputStream, OutputStream outputStream) {
        byte[] bArr = new byte[4096];
        while (true) {
            int read = inputStream.read(bArr);
            if (read == -1) {
                return;
            }
            outputStream.write(bArr, 0, read);
            outputStream.flush();
        }
    }
}
