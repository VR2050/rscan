package p005b.p085c.p102c.p103a.p104a.p107b;

import java.io.File;
import java.io.FileFilter;
import java.util.regex.Pattern;

/* renamed from: b.c.c.a.a.b.b */
/* loaded from: classes.dex */
public final class C1394b implements FileFilter {
    public C1394b(C1393a c1393a) {
    }

    @Override // java.io.FileFilter
    public final boolean accept(File file) {
        return Pattern.matches("cpu[0-9]+", file.getName());
    }
}
