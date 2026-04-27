package L;

import M.h;
import M.j;
import android.webkit.WebSettings;

/* JADX INFO: loaded from: classes.dex */
public abstract class e {
    private static M.g a(WebSettings webSettings) {
        return j.c().a(webSettings);
    }

    public static void b(WebSettings webSettings, int i3) {
        h hVar = h.FORCE_DARK;
        if (hVar.f()) {
            webSettings.setForceDark(i3);
        } else {
            if (!hVar.g()) {
                throw h.a();
            }
            a(webSettings).a(i3);
        }
    }

    public static void c(WebSettings webSettings, int i3) {
        if (!h.FORCE_DARK_STRATEGY.g()) {
            throw h.a();
        }
        a(webSettings).b(i3);
    }
}
