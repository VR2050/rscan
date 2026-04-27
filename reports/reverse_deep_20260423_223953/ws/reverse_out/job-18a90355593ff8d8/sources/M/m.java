package M;

import android.webkit.WebView;
import org.chromium.support_lib_boundary.WebViewProviderBoundaryInterface;
import org.chromium.support_lib_boundary.WebViewProviderFactoryBoundaryInterface;
import org.chromium.support_lib_boundary.WebkitToCompatConverterBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public class m implements l {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    WebViewProviderFactoryBoundaryInterface f1806a;

    public m(WebViewProviderFactoryBoundaryInterface webViewProviderFactoryBoundaryInterface) {
        this.f1806a = webViewProviderFactoryBoundaryInterface;
    }

    @Override // M.l
    public String[] a() {
        return this.f1806a.getSupportedFeatures();
    }

    @Override // M.l
    public WebViewProviderBoundaryInterface createWebView(WebView webView) {
        return (WebViewProviderBoundaryInterface) S2.a.a(WebViewProviderBoundaryInterface.class, this.f1806a.createWebView(webView));
    }

    @Override // M.l
    public WebkitToCompatConverterBoundaryInterface getWebkitToCompatConverter() {
        return (WebkitToCompatConverterBoundaryInterface) S2.a.a(WebkitToCompatConverterBoundaryInterface.class, this.f1806a.getWebkitToCompatConverter());
    }
}
