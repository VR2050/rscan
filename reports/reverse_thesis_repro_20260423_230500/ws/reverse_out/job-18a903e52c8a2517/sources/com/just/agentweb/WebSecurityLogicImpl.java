package com.just.agentweb;

import android.os.Build;
import android.webkit.WebView;
import androidx.collection.ArrayMap;
import com.just.agentweb.AgentWeb;

/* JADX INFO: loaded from: classes3.dex */
public class WebSecurityLogicImpl implements WebSecurityCheckLogic {
    private String TAG = getClass().getSimpleName();
    private int webviewType;

    public static WebSecurityLogicImpl getInstance(int webViewType) {
        return new WebSecurityLogicImpl(webViewType);
    }

    public WebSecurityLogicImpl(int webViewType) {
        this.webviewType = webViewType;
    }

    @Override // com.just.agentweb.WebSecurityCheckLogic
    public void dealHoneyComb(WebView view) {
        if (11 > Build.VERSION.SDK_INT || Build.VERSION.SDK_INT > 17) {
            return;
        }
        view.removeJavascriptInterface("searchBoxJavaBridge_");
        view.removeJavascriptInterface("accessibility");
        view.removeJavascriptInterface("accessibilityTraversal");
    }

    @Override // com.just.agentweb.WebSecurityCheckLogic
    public void dealJsInterface(ArrayMap<String, Object> objects, AgentWeb.SecurityType securityType) {
        if (securityType == AgentWeb.SecurityType.STRICT_CHECK && this.webviewType != 2 && Build.VERSION.SDK_INT < 17) {
            LogUtils.e(this.TAG, "Give up all inject objects");
            objects.clear();
            System.gc();
        }
    }
}
