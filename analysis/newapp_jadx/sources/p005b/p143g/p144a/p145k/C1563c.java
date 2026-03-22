package p005b.p143g.p144a.p145k;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.k.c */
/* loaded from: classes.dex */
public final class C1563c {

    /* renamed from: a */
    public static final Charset f1921a = Charset.forName("US-ASCII");

    static {
        Charset.forName("UTF-8");
    }

    /* renamed from: a */
    public static void m803a(File file) {
        File[] listFiles = file.listFiles();
        if (listFiles == null) {
            throw new IOException(C1499a.m634t("not a readable directory: ", file));
        }
        for (File file2 : listFiles) {
            if (file2.isDirectory()) {
                m803a(file2);
            }
            if (!file2.delete()) {
                throw new IOException(C1499a.m634t("failed to delete file: ", file2));
            }
        }
    }
}
