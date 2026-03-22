package p005b.p006a.p007a.p008a.p009a;

import java.io.File;

/* renamed from: b.a.a.a.a.l */
/* loaded from: classes2.dex */
public final class C0856l {
    /* renamed from: a */
    public static final boolean m192a(File file) {
        if (file.isDirectory()) {
            String[] list = file.list();
            if (list == null) {
                return file.delete();
            }
            int length = list.length - 1;
            if (length >= 0) {
                int i2 = 0;
                while (true) {
                    int i3 = i2 + 1;
                    if (!m192a(new File(file, list[i2]))) {
                        return false;
                    }
                    if (i3 > length) {
                        break;
                    }
                    i2 = i3;
                }
            }
        }
        return file.delete();
    }
}
