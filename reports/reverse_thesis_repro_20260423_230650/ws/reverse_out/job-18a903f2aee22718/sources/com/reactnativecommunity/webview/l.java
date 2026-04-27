package com.reactnativecommunity.webview;

import android.app.Activity;
import android.app.DownloadManager;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.DownloadListener;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.uimanager.B0;
import d1.AbstractC0508d;
import f1.C0527a;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class l {

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    public static final a f8614C = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final boolean f8617a;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f8620d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f8621e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private String f8622f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private String f8623g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f8624h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private ReadableMap f8625i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private String f8626j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private String f8627k;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f8618b = "RNCWebViewManagerImpl";

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private i f8619c = new i() { // from class: com.reactnativecommunity.webview.j
        @Override // com.reactnativecommunity.webview.i
        public final void a(WebView webView) {
            l.k(webView);
        }
    };

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final String f8628l = "UTF-8";

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final String f8629m = "text/html";

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final String f8630n = "POST";

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final String f8631o = "about:blank";

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final String f8632p = "Downloading";

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final String f8633q = "Cannot download files as permission was denied. Please provide permission to write to storage, in order to download files.";

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final int f8634r = 1;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final int f8635s = 2;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final int f8636t = 3;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final int f8637u = 4;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final int f8638v = 5;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private final int f8639w = 6;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private final int f8640x = 7;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private final int f8641y = 8;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private final int f8642z = 1000;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private final int f8615A = 1001;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final int f8616B = 1002;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public static final class b extends com.reactnativecommunity.webview.c {
        b(e eVar) {
            super(eVar);
        }

        @Override // android.webkit.WebChromeClient
        public Bitmap getDefaultVideoPoster() {
            return Bitmap.createBitmap(50, 50, Bitmap.Config.ARGB_8888);
        }
    }

    public static final class c extends com.reactnativecommunity.webview.c {

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        final /* synthetic */ Activity f8643p;

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        final /* synthetic */ int f8644q;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        c(e eVar, Activity activity, int i3) {
            super(eVar);
            this.f8643p = activity;
            this.f8644q = i3;
        }

        @Override // android.webkit.WebChromeClient
        public Bitmap getDefaultVideoPoster() {
            return Bitmap.createBitmap(50, 50, Bitmap.Config.ARGB_8888);
        }

        @Override // android.webkit.WebChromeClient
        public void onHideCustomView() {
            if (this.f8558c == null) {
                return;
            }
            ViewGroup viewGroupC = c();
            if (viewGroupC.getRootView() != this.f8557b.getRootView()) {
                this.f8557b.getRootView().setVisibility(0);
            } else {
                this.f8557b.setVisibility(0);
            }
            this.f8643p.getWindow().clearFlags(512);
            viewGroupC.removeView(this.f8558c);
            this.f8559d.onCustomViewHidden();
            this.f8558c = null;
            this.f8559d = null;
            this.f8643p.setRequestedOrientation(this.f8644q);
            this.f8557b.getThemedReactContext().removeLifecycleEventListener(this);
        }

        @Override // android.webkit.WebChromeClient
        public void onShowCustomView(View view, WebChromeClient.CustomViewCallback customViewCallback) {
            t2.j.f(view, "view");
            t2.j.f(customViewCallback, "callback");
            if (this.f8558c != null) {
                customViewCallback.onCustomViewHidden();
                return;
            }
            this.f8558c = view;
            this.f8559d = customViewCallback;
            this.f8643p.setRequestedOrientation(-1);
            this.f8558c.setSystemUiVisibility(7942);
            this.f8643p.getWindow().setFlags(512, 512);
            this.f8558c.setBackgroundColor(-16777216);
            ViewGroup viewGroupC = c();
            viewGroupC.addView(this.f8558c, com.reactnativecommunity.webview.c.f8556o);
            if (viewGroupC.getRootView() != this.f8557b.getRootView()) {
                this.f8557b.getRootView().setVisibility(8);
            } else {
                this.f8557b.setVisibility(8);
            }
            this.f8557b.getThemedReactContext().addLifecycleEventListener(this);
        }
    }

    public l(boolean z3) {
        this.f8617a = z3;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void f(e eVar, l lVar, String str, String str2, String str3, String str4, long j3) {
        eVar.setIgnoreErrFailedForThisURL(str);
        RNCWebViewModule rNCWebViewModule = (RNCWebViewModule) eVar.getReactApplicationContext().getNativeModule(RNCWebViewModule.class);
        if (rNCWebViewModule == null) {
            return;
        }
        try {
            DownloadManager.Request request = new DownloadManager.Request(Uri.parse(str));
            String strA = r.a(str, str3, str4);
            t2.j.c(strA);
            String strB = m.a().b(strA, "_");
            String str5 = "Downloading " + strB;
            try {
                URL url = new URL(str);
                request.addRequestHeader("Cookie", CookieManager.getInstance().getCookie(url.getProtocol() + "://" + url.getHost()));
            } catch (MalformedURLException e3) {
                Log.w(lVar.f8618b, "Error getting cookie for DownloadManager", e3);
            }
            request.addRequestHeader("User-Agent", str2);
            request.setTitle(strB);
            request.setDescription(str5);
            request.allowScanningByMediaScanner();
            request.setNotificationVisibility(1);
            request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, strB);
            rNCWebViewModule.setDownloadRequest(request);
            if (rNCWebViewModule.grantFileDownloaderPermissions(lVar.h(), lVar.i())) {
                rNCWebViewModule.downloadFile(lVar.h());
            }
        } catch (IllegalArgumentException e4) {
            Log.w(lVar.f8618b, "Unsupported URI, aborting download", e4);
        }
    }

    private final void f0(q qVar) {
        e webView = qVar.getWebView();
        if (this.f8626j != null) {
            webView.getSettings().setUserAgentString(this.f8626j);
        } else if (this.f8627k != null) {
            webView.getSettings().setUserAgentString(this.f8627k);
        } else {
            webView.getSettings().setUserAgentString(WebSettings.getDefaultUserAgent(webView.getContext()));
        }
    }

    private final String h() {
        String str = this.f8622f;
        return str == null ? this.f8632p : str;
    }

    private final void h0(e eVar) {
        Activity currentActivity = eVar.getThemedReactContext().getCurrentActivity();
        if (this.f8620d && currentActivity != null) {
            c cVar = new c(eVar, currentActivity, currentActivity.getRequestedOrientation());
            cVar.f(this.f8621e);
            cVar.g(this.f8624h);
            eVar.setWebChromeClient(cVar);
            return;
        }
        com.reactnativecommunity.webview.c cVar2 = (com.reactnativecommunity.webview.c) eVar.getWebChromeClient();
        if (cVar2 != null) {
            cVar2.onHideCustomView();
        }
        b bVar = new b(eVar);
        bVar.f(this.f8621e);
        bVar.g(this.f8624h);
        eVar.setWebChromeClient(bVar);
    }

    private final String i() {
        String str = this.f8623g;
        return str == null ? this.f8633q : str;
    }

    private final void j(q qVar, ReadableMap readableMap) {
        byte[] bytes;
        e webView = qVar.getWebView();
        if (readableMap != null) {
            if (readableMap.hasKey("html")) {
                String string = readableMap.getString("html");
                String string2 = readableMap.hasKey("baseUrl") ? readableMap.getString("baseUrl") : "";
                t2.j.c(string);
                webView.loadDataWithBaseURL(string2, string, this.f8629m, this.f8628l, null);
                return;
            }
            if (readableMap.hasKey("uri")) {
                String string3 = readableMap.getString("uri");
                String url = webView.getUrl();
                if (url == null || !t2.j.b(url, string3)) {
                    if (readableMap.hasKey("method") && z2.g.j(readableMap.getString("method"), this.f8630n, true)) {
                        if (readableMap.hasKey("body")) {
                            String string4 = readableMap.getString("body");
                            try {
                                t2.j.c(string4);
                                Charset charsetForName = Charset.forName("UTF-8");
                                t2.j.e(charsetForName, "forName(...)");
                                bytes = string4.getBytes(charsetForName);
                                t2.j.e(bytes, "getBytes(...)");
                            } catch (UnsupportedEncodingException unused) {
                                t2.j.c(string4);
                                bytes = string4.getBytes(z2.d.f10544b);
                                t2.j.e(bytes, "getBytes(...)");
                            }
                        } else {
                            bytes = null;
                        }
                        if (bytes == null) {
                            bytes = new byte[0];
                        }
                        t2.j.c(string3);
                        webView.postUrl(string3, bytes);
                        return;
                    }
                    HashMap map = new HashMap();
                    if (readableMap.hasKey("headers")) {
                        if (this.f8617a) {
                            ReadableArray array = readableMap.getArray("headers");
                            t2.j.c(array);
                            Iterator<Object> it = array.toArrayList().iterator();
                            t2.j.e(it, "iterator(...)");
                            while (it.hasNext()) {
                                Object next = it.next();
                                t2.j.d(next, "null cannot be cast to non-null type java.util.HashMap<kotlin.String, kotlin.String>");
                                HashMap map2 = (HashMap) next;
                                String str = (String) map2.get("name");
                                if (str == null) {
                                    str = "";
                                }
                                String str2 = (String) map2.get("value");
                                if (str2 == null) {
                                    str2 = "";
                                }
                                Locale locale = Locale.ENGLISH;
                                t2.j.e(locale, "ENGLISH");
                                String lowerCase = str.toLowerCase(locale);
                                t2.j.e(lowerCase, "toLowerCase(...)");
                                if (t2.j.b("user-agent", lowerCase)) {
                                    webView.getSettings().setUserAgentString(str2);
                                } else {
                                    map.put(str, str2);
                                }
                            }
                        } else {
                            ReadableMap map3 = readableMap.getMap("headers");
                            t2.j.c(map3);
                            ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = map3.keySetIterator();
                            while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
                                String strNextKey = readableMapKeySetIteratorKeySetIterator.nextKey();
                                Locale locale2 = Locale.ENGLISH;
                                t2.j.e(locale2, "ENGLISH");
                                String lowerCase2 = strNextKey.toLowerCase(locale2);
                                t2.j.e(lowerCase2, "toLowerCase(...)");
                                if (t2.j.b("user-agent", lowerCase2)) {
                                    webView.getSettings().setUserAgentString(map3.getString(strNextKey));
                                } else {
                                    map.put(strNextKey, map3.getString(strNextKey));
                                }
                            }
                        }
                    }
                    t2.j.c(string3);
                    webView.loadUrl(string3, map);
                    return;
                }
                return;
            }
        }
        webView.loadUrl(this.f8631o);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void k(WebView webView) {
    }

    public final void A(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setGeolocationEnabled(z3);
    }

    public final void B(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        this.f8624h = z3;
        h0(webView);
    }

    public final void C(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().setHasScrollEvent(z3);
    }

    public final void D(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        if (z3) {
            CookieManager.getInstance().removeAllCookies(null);
            webView.getSettings().setCacheMode(2);
            webView.clearHistory();
            webView.clearCache(true);
            webView.clearFormData();
            webView.getSettings().setSavePassword(false);
            webView.getSettings().setSaveFormData(false);
        }
    }

    public final void E(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().f8572b = str;
    }

    public final void F(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().f8573c = str;
    }

    public final void G(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().f8577g = z3;
    }

    public final void H(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().f8576f = z3;
    }

    public final void I(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().setInjectedJavaScriptObject(str);
    }

    public final void J(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setJavaScriptCanOpenWindowsAutomatically(z3);
    }

    public final void K(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setJavaScriptEnabled(z3);
    }

    public final void L(String str) {
        this.f8623g = str;
    }

    public final void M(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setMediaPlaybackRequiresUserGesture(z3);
    }

    public final void N(q qVar, ReadableArray readableArray) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        if (readableArray == null) {
            webView.setMenuCustomItems(null);
            return;
        }
        ArrayList<Object> arrayList = readableArray.toArrayList();
        t2.j.d(arrayList, "null cannot be cast to non-null type kotlin.collections.List<kotlin.collections.Map<kotlin.String, kotlin.String>>");
        webView.setMenuCustomItems(arrayList);
    }

    public final void O(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().setMessagingEnabled(z3);
    }

    public final void P(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().f8579i = str;
    }

    public final void Q(q qVar, int i3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setMinimumFontSize(i3);
    }

    public final void R(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        if (str == null || t2.j.b("never", str)) {
            webView.getSettings().setMixedContentMode(1);
        } else if (t2.j.b("always", str)) {
            webView.getSettings().setMixedContentMode(0);
        } else if (t2.j.b("compatibility", str)) {
            webView.getSettings().setMixedContentMode(2);
        }
    }

    public final void S(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().f8585o = z3;
    }

    public final void T(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        int i3 = 0;
        if (str != null) {
            int iHashCode = str.hashCode();
            if (iHashCode == -1414557169) {
                str.equals("always");
            } else if (iHashCode != 104712844) {
                if (iHashCode == 951530617 && str.equals("content")) {
                    i3 = 1;
                }
            } else if (str.equals("never")) {
                i3 = 2;
            }
        }
        webView.setOverScrollMode(i3);
    }

    public final void U(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setSaveFormData(!z3);
    }

    public final void V(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        webView.getSettings().setLoadWithOverviewMode(z3);
        webView.getSettings().setUseWideViewPort(z3);
    }

    public final void W(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setBuiltInZoomControls(z3);
    }

    public final void X(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setDisplayZoomControls(z3);
    }

    public final void Y(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setSupportMultipleWindows(z3);
    }

    public final void Z(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().setHorizontalScrollBarEnabled(z3);
    }

    public final void a0(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().setVerticalScrollBarEnabled(z3);
    }

    public final void b0(q qVar, ReadableMap readableMap) {
        t2.j.f(qVar, "viewWrapper");
        this.f8625i = readableMap;
    }

    public final e c(B0 b02) {
        t2.j.f(b02, "context");
        return new e(b02);
    }

    public final void c0(q qVar, int i3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setTextZoom(i3);
    }

    public final q d(B0 b02) {
        t2.j.f(b02, "context");
        return e(b02, c(b02));
    }

    public final void d0(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        CookieManager.getInstance().setAcceptThirdPartyCookies(qVar.getWebView(), z3);
    }

    public final q e(B0 b02, final e eVar) {
        t2.j.f(b02, "context");
        t2.j.f(eVar, "webView");
        h0(eVar);
        b02.addLifecycleEventListener(eVar);
        this.f8619c.a(eVar);
        WebSettings settings = eVar.getSettings();
        t2.j.e(settings, "getSettings(...)");
        settings.setBuiltInZoomControls(true);
        settings.setDisplayZoomControls(false);
        settings.setDomStorageEnabled(true);
        settings.setSupportMultipleWindows(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setMixedContentMode(1);
        eVar.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
        if (C0527a.f9198b) {
            WebView.setWebContentsDebuggingEnabled(true);
        }
        eVar.setDownloadListener(new DownloadListener() { // from class: com.reactnativecommunity.webview.k
            @Override // android.webkit.DownloadListener
            public final void onDownloadStart(String str, String str2, String str3, String str4, long j3) {
                l.f(eVar, this, str, str2, str3, str4, j3);
            }
        });
        return new q(b02, eVar);
    }

    public final void e0(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        this.f8626j = str;
        f0(qVar);
    }

    public final Map g() {
        return AbstractC0508d.a().b("goBack", Integer.valueOf(this.f8634r)).b("goForward", Integer.valueOf(this.f8635s)).b("reload", Integer.valueOf(this.f8636t)).b("stopLoading", Integer.valueOf(this.f8637u)).b("postMessage", Integer.valueOf(this.f8638v)).b("injectJavaScript", Integer.valueOf(this.f8639w)).b("loadUrl", Integer.valueOf(this.f8640x)).b("requestFocus", Integer.valueOf(this.f8641y)).b("clearFormData", Integer.valueOf(this.f8642z)).b("clearCache", Integer.valueOf(this.f8615A)).b("clearHistory", Integer.valueOf(this.f8616B)).a();
    }

    public final void g0(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        WebView.setWebContentsDebuggingEnabled(z3);
    }

    public final void l(q qVar) {
        t2.j.f(qVar, "viewWrapper");
        ReadableMap readableMap = this.f8625i;
        if (readableMap != null) {
            j(qVar, readableMap);
        }
        this.f8625i = null;
    }

    public final void m(q qVar) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        webView.getThemedReactContext().removeLifecycleEventListener(webView);
        webView.c();
        webView.f8588r = null;
    }

    public final void n(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setAllowFileAccess(z3);
    }

    public final void o(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setAllowFileAccessFromFileURLs(z3);
    }

    public final void p(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setAllowUniversalAccessFromFileURLs(z3);
    }

    public final void q(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        this.f8620d = z3;
        h0(webView);
    }

    public final void r(q qVar, boolean z3) {
        WebChromeClient webChromeClient;
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        this.f8621e = z3;
        if (Build.VERSION.SDK_INT < 26 || (webChromeClient = webView.getWebChromeClient()) == null || !(webChromeClient instanceof com.reactnativecommunity.webview.c)) {
            return;
        }
        ((com.reactnativecommunity.webview.c) webChromeClient).f(z3);
    }

    public final void s(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().setLayerType(t2.j.b(str, "hardware") ? 2 : t2.j.b(str, "software") ? 1 : 0, null);
    }

    public final void t(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        if (str != null) {
            this.f8627k = WebSettings.getDefaultUserAgent(qVar.getWebView().getContext()) + " " + str;
        } else {
            this.f8627k = null;
        }
        f0(qVar);
    }

    public final void u(q qVar, ReadableMap readableMap) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().setBasicAuthCredential((readableMap != null && readableMap.hasKey("username") && readableMap.hasKey("password")) ? new com.reactnativecommunity.webview.a(readableMap.getString("username"), readableMap.getString("password")) : null);
    }

    public final void v(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setCacheMode(z3 ? -1 : 2);
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public final void w(q qVar, String str) {
        t2.j.f(qVar, "viewWrapper");
        WebSettings settings = qVar.getWebView().getSettings();
        int i3 = -1;
        if (str != null) {
            switch (str.hashCode()) {
                case -2059164003:
                    if (str.equals("LOAD_NO_CACHE")) {
                        i3 = 2;
                    }
                    break;
                case -1215135800:
                    str.equals("LOAD_DEFAULT");
                    break;
                case -873877826:
                    if (str.equals("LOAD_CACHE_ELSE_NETWORK")) {
                        i3 = 1;
                    }
                    break;
                case 1548620642:
                    if (str.equals("LOAD_CACHE_ONLY")) {
                        i3 = 3;
                    }
                    break;
            }
        }
        settings.setCacheMode(i3);
    }

    public final void x(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        qVar.getWebView().getSettings().setDomStorageEnabled(z3);
    }

    public final void y(String str) {
        this.f8622f = str;
    }

    public final void z(q qVar, boolean z3) {
        t2.j.f(qVar, "viewWrapper");
        e webView = qVar.getWebView();
        if (Build.VERSION.SDK_INT > 28) {
            if (L.g.a("FORCE_DARK")) {
                L.e.b(webView.getSettings(), z3 ? 2 : 0);
            }
            if (z3 && L.g.a("FORCE_DARK_STRATEGY")) {
                L.e.c(webView.getSettings(), 2);
            }
        }
    }
}
