package p005b.p172h.p173a.p174r;

import java.io.File;
import java.util.Comparator;

/* renamed from: b.h.a.r.d */
/* loaded from: classes.dex */
public final class C1832d implements Comparator<File> {
    public C1832d(C1831c c1831c) {
    }

    @Override // java.util.Comparator
    public int compare(File file, File file2) {
        long lastModified = file.lastModified();
        long lastModified2 = file2.lastModified();
        if (lastModified < lastModified2) {
            return -1;
        }
        return lastModified == lastModified2 ? 0 : 1;
    }
}
