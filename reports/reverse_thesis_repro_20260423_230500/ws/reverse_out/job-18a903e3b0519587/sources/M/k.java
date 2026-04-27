package M;

import L.f;
import org.chromium.support_lib_boundary.WebViewProviderBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public class k {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    WebViewProviderBoundaryInterface f1805a;

    public k(WebViewProviderBoundaryInterface webViewProviderBoundaryInterface) {
        this.f1805a = webViewProviderBoundaryInterface;
    }

    public void a(String str, String[] strArr, f.a aVar) {
        this.f1805a.addWebMessageListener(str, strArr, S2.a.c(new e(aVar)));
    }
}
