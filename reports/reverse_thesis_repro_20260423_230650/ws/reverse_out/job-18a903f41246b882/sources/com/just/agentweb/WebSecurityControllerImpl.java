package com.just.agentweb;

import android.os.Build;
import android.webkit.WebView;
import androidx.collection.ArrayMap;
import com.just.agentweb.AgentWeb;

/* JADX INFO: loaded from: classes3.dex */
public class WebSecurityControllerImpl implements WebSecurityController<WebSecurityCheckLogic> {
    private ArrayMap<String, Object> mMap;
    private AgentWeb.SecurityType mSecurityType;
    private WebView mWebView;

    public WebSecurityControllerImpl(WebView view, ArrayMap<String, Object> map, AgentWeb.SecurityType securityType) {
        this.mWebView = view;
        this.mMap = map;
        this.mSecurityType = securityType;
    }

    @Override // com.just.agentweb.WebSecurityController
    public void check(WebSecurityCheckLogic webSecurityCheckLogic) {
        if (Build.VERSION.SDK_INT > 11) {
            webSecurityCheckLogic.dealHoneyComb(this.mWebView);
        }
        if (this.mMap != null && this.mSecurityType == AgentWeb.SecurityType.STRICT_CHECK && !this.mMap.isEmpty()) {
            webSecurityCheckLogic.dealJsInterface(this.mMap, this.mSecurityType);
        }
    }
}
