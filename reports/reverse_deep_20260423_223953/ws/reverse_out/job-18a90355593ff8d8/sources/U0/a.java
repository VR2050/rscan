package U0;

import U0.b;
import android.os.Trace;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a implements b.c {
    @Override // U0.b.c
    public void a(String str) {
        j.f(str, "name");
        if (isTracing()) {
            Trace.beginSection(str);
        }
    }

    @Override // U0.b.c
    public void b() {
        if (isTracing()) {
            Trace.endSection();
        }
    }

    @Override // U0.b.c
    public boolean isTracing() {
        return false;
    }
}
