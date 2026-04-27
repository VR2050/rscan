package z;

import android.text.Editable;
import androidx.emoji2.text.o;

/* JADX INFO: renamed from: z.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
final class C0735b extends Editable.Factory {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final Object f10512a = new Object();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static volatile Editable.Factory f10513b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static Class f10514c;

    private C0735b() {
        try {
            f10514c = Class.forName("android.text.DynamicLayout$ChangeWatcher", false, C0735b.class.getClassLoader());
        } catch (Throwable unused) {
        }
    }

    public static Editable.Factory getInstance() {
        if (f10513b == null) {
            synchronized (f10512a) {
                try {
                    if (f10513b == null) {
                        f10513b = new C0735b();
                    }
                } finally {
                }
            }
        }
        return f10513b;
    }

    @Override // android.text.Editable.Factory
    public Editable newEditable(CharSequence charSequence) {
        Class cls = f10514c;
        return cls != null ? o.c(cls, charSequence) : super.newEditable(charSequence);
    }
}
