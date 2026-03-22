package p005b.p139f.p140a.p142b;

import java.io.File;

/* renamed from: b.f.a.b.c */
/* loaded from: classes.dex */
public final class C1533c {

    /* renamed from: a */
    public static final /* synthetic */ int f1714a = 0;

    static {
        System.getProperty("line.separator");
    }

    /* renamed from: a */
    public static boolean m687a(File file) {
        return file != null && (!file.exists() ? !file.mkdirs() : !file.isDirectory());
    }
}
