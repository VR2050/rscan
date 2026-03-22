package p005b.p006a.p007a.p008a.p009a;

import android.text.TextUtils;
import java.io.File;
import java.math.BigDecimal;

/* renamed from: b.a.a.a.a.v */
/* loaded from: classes2.dex */
public class C0874v {

    /* renamed from: a */
    public static C0874v f311a;

    /* renamed from: c */
    public static String m201c(double d2) {
        double d3 = d2 / 1024.0d;
        if (d3 < 1.0d) {
            return d2 + "Byte";
        }
        double d4 = d3 / 1024.0d;
        if (d4 < 1.0d) {
            return new BigDecimal(Double.toString(d3)).setScale(2, 4).toPlainString() + "KB";
        }
        double d5 = d4 / 1024.0d;
        if (d5 < 1.0d) {
            return new BigDecimal(Double.toString(d4)).setScale(2, 4).toPlainString() + "MB";
        }
        double d6 = d5 / 1024.0d;
        if (d6 < 1.0d) {
            return new BigDecimal(Double.toString(d5)).setScale(2, 4).toPlainString() + "GB";
        }
        return new BigDecimal(d6).setScale(2, 4).toPlainString() + "TB";
    }

    /* renamed from: a */
    public final void m202a(String str, boolean z) {
        if (TextUtils.isEmpty(str)) {
            return;
        }
        try {
            File file = new File(str);
            if (file.isDirectory()) {
                for (File file2 : file.listFiles()) {
                    m202a(file2.getAbsolutePath(), true);
                }
            }
            if (z) {
                if (!file.isDirectory()) {
                    file.delete();
                } else if (file.listFiles().length == 0) {
                    file.delete();
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    /* renamed from: b */
    public final long m203b(File file) {
        long j2 = 0;
        try {
            for (File file2 : file.listFiles()) {
                j2 += file2.isDirectory() ? m203b(file2) : file2.length();
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return j2;
    }
}
