package M;

import android.webkit.WebSettings;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;
import org.chromium.support_lib_boundary.WebkitToCompatConverterBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public class n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final WebkitToCompatConverterBoundaryInterface f1807a;

    public n(WebkitToCompatConverterBoundaryInterface webkitToCompatConverterBoundaryInterface) {
        this.f1807a = webkitToCompatConverterBoundaryInterface;
    }

    public g a(WebSettings webSettings) {
        return new g((WebSettingsBoundaryInterface) S2.a.a(WebSettingsBoundaryInterface.class, this.f1807a.convertSettings(webSettings)));
    }
}
