package com.reactnativecommunity.webview;

import L.f;
import android.graphics.Rect;
import android.net.Uri;
import android.text.TextUtils;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.H0;
import e2.AbstractC0521e;
import g2.C0534a;
import g2.C0540g;
import java.util.List;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes.dex */
public class e extends WebView implements LifecycleEventListener {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected String f8572b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected String f8573c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected C0123e f8574d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    protected f.a f8575e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    protected boolean f8576f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    protected boolean f8577g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    protected boolean f8578h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    protected String f8579i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    protected RNCWebViewMessagingModule f8580j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    protected h f8581k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    protected boolean f8582l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private com.facebook.react.views.scroll.c f8583m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    protected boolean f8584n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    protected boolean f8585o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    protected d f8586p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    protected List f8587q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    WebChromeClient f8588r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    protected String f8589s;

    class a extends ActionMode.Callback2 {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ ActionMode.Callback f8590a;

        /* JADX INFO: renamed from: com.reactnativecommunity.webview.e$a$a, reason: collision with other inner class name */
        class C0122a implements ValueCallback {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ MenuItem f8592a;

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ WritableMap f8593b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ ActionMode f8594c;

            C0122a(MenuItem menuItem, WritableMap writableMap, ActionMode actionMode) {
                this.f8592a = menuItem;
                this.f8593b = writableMap;
                this.f8594c = actionMode;
            }

            /* JADX WARN: Type inference fix 'apply assigned field type' failed
            java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
            	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
            	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
            	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
             */
            @Override // android.webkit.ValueCallback
            /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
            public void onReceiveValue(String str) {
                String string;
                Map map = (Map) e.this.f8587q.get(this.f8592a.getItemId());
                this.f8593b.putString("label", (String) map.get("label"));
                this.f8593b.putString("key", (String) map.get("key"));
                try {
                    string = new JSONObject(str).getString("selection");
                } catch (JSONException unused) {
                    string = "";
                }
                this.f8593b.putString("selectedText", string);
                e eVar = e.this;
                eVar.g(eVar, new C0534a(q.a(e.this), this.f8593b));
                this.f8594c.finish();
            }
        }

        a(ActionMode.Callback callback) {
            this.f8590a = callback;
        }

        @Override // android.view.ActionMode.Callback
        public boolean onActionItemClicked(ActionMode actionMode, MenuItem menuItem) {
            e.this.evaluateJavascript("(function(){return {selection: window.getSelection().toString()} })()", new C0122a(menuItem, Arguments.createMap(), actionMode));
            return true;
        }

        @Override // android.view.ActionMode.Callback
        public boolean onCreateActionMode(ActionMode actionMode, Menu menu) {
            for (int i3 = 0; i3 < e.this.f8587q.size(); i3++) {
                menu.add(0, i3, i3, (CharSequence) ((Map) e.this.f8587q.get(i3)).get("label"));
            }
            return true;
        }

        @Override // android.view.ActionMode.Callback
        public void onDestroyActionMode(ActionMode actionMode) {
        }

        @Override // android.view.ActionMode.Callback2
        public void onGetContentRect(ActionMode actionMode, View view, Rect rect) {
            ActionMode.Callback callback = this.f8590a;
            if (callback instanceof ActionMode.Callback2) {
                ((ActionMode.Callback2) callback).onGetContentRect(actionMode, view, rect);
            } else {
                super.onGetContentRect(actionMode, view, rect);
            }
        }

        @Override // android.view.ActionMode.Callback
        public boolean onPrepareActionMode(ActionMode actionMode, Menu menu) {
            return false;
        }
    }

    class b implements f.a {
        b() {
        }

        @Override // L.f.a
        public void a(WebView webView, L.b bVar, Uri uri, boolean z3, L.a aVar) {
            e.this.j(bVar.a(), uri.toString());
        }
    }

    class c implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ WebView f8597b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f8598c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ String f8599d;

        c(WebView webView, String str, String str2) {
            this.f8597b = webView;
            this.f8598c = str;
            this.f8599d = str2;
        }

        @Override // java.lang.Runnable
        public void run() {
            h hVar = e.this.f8581k;
            if (hVar == null) {
                return;
            }
            WritableMap writableMapA = hVar.a(this.f8597b, this.f8598c);
            writableMapA.putString("data", this.f8599d);
            e eVar = e.this;
            if (eVar.f8580j != null) {
                eVar.e(writableMapA);
            } else {
                eVar.g(this.f8597b, new C0540g(q.a(this.f8597b), writableMapA));
            }
        }
    }

    protected static class d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private boolean f8601a = false;

        protected d() {
        }

        public boolean a() {
            return this.f8601a;
        }

        public void b(boolean z3) {
            this.f8601a = z3;
        }
    }

    /* JADX INFO: renamed from: com.reactnativecommunity.webview.e$e, reason: collision with other inner class name */
    protected class C0123e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private String f8602a = "RNCWebViewBridge";

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        e f8603b;

        C0123e(e eVar) {
            this.f8603b = eVar;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void b(String str) {
            e eVar = this.f8603b;
            eVar.j(str, eVar.getUrl());
        }

        @JavascriptInterface
        public void postMessage(final String str) {
            if (this.f8603b.getMessagingEnabled()) {
                this.f8603b.post(new Runnable() { // from class: com.reactnativecommunity.webview.f
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f8605b.b(str);
                    }
                });
            } else {
                Y.a.I(this.f8602a, "ReactNativeWebView.postMessage method was called but messaging is disabled. Pass an onMessage handler to the WebView.");
            }
        }
    }

    public e(B0 b02) {
        super(b02);
        this.f8575e = null;
        this.f8576f = true;
        this.f8577g = true;
        this.f8578h = false;
        this.f8582l = false;
        this.f8584n = false;
        this.f8585o = false;
        this.f8589s = null;
        this.f8580j = (RNCWebViewMessagingModule) ((B0) getContext()).b().getJSModule(RNCWebViewMessagingModule.class);
        this.f8586p = new d();
    }

    private void i() {
        String str;
        if (getSettings().getJavaScriptEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("(function(){\n    window.ReactNativeWebView = window.ReactNativeWebView || {};\n    window.ReactNativeWebView.injectedObjectJson = function () { return ");
            if (this.f8589s == null) {
                str = null;
            } else {
                str = "`" + this.f8589s + "`";
            }
            sb.append(str);
            sb.append("; };\n})();");
            h(sb.toString());
        }
    }

    public void a() {
        String str;
        if (!getSettings().getJavaScriptEnabled() || (str = this.f8572b) == null || TextUtils.isEmpty(str)) {
            return;
        }
        h("(function() {\n" + this.f8572b + ";\n})();");
        i();
    }

    public void b() {
        String str;
        if (!getSettings().getJavaScriptEnabled() || (str = this.f8573c) == null || TextUtils.isEmpty(str)) {
            return;
        }
        h("(function() {\n" + this.f8573c + ";\n})();");
        i();
    }

    protected void c() {
        setWebViewClient(null);
        destroy();
    }

    protected void d(e eVar) {
        if (L.g.a("WEB_MESSAGE_LISTENER")) {
            if (this.f8575e == null) {
                this.f8575e = new b();
                L.f.a(eVar, "ReactNativeWebView", AbstractC0521e.a(new Object[]{"*"}), this.f8575e);
            }
        } else if (this.f8574d == null) {
            C0123e c0123e = new C0123e(eVar);
            this.f8574d = c0123e;
            addJavascriptInterface(c0123e, "ReactNativeWebView");
        }
        i();
    }

    @Override // android.webkit.WebView
    public void destroy() {
        WebChromeClient webChromeClient = this.f8588r;
        if (webChromeClient != null) {
            webChromeClient.onHideCustomView();
        }
        super.destroy();
    }

    protected void e(WritableMap writableMap) {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        writableNativeMap.putMap("nativeEvent", writableMap);
        writableNativeMap.putString("messagingModuleName", this.f8579i);
        this.f8580j.onMessage(writableNativeMap);
    }

    protected boolean f(WritableMap writableMap) {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        writableNativeMap.putMap("nativeEvent", writableMap);
        writableNativeMap.putString("messagingModuleName", this.f8579i);
        this.f8580j.onShouldStartLoadWithRequest(writableNativeMap);
        return true;
    }

    protected void g(WebView webView, O1.d dVar) {
        H0.c(getThemedReactContext(), q.a(webView)).g(dVar);
    }

    public boolean getMessagingEnabled() {
        return this.f8578h;
    }

    public h getRNCWebViewClient() {
        return this.f8581k;
    }

    public ReactApplicationContext getReactApplicationContext() {
        return getThemedReactContext().b();
    }

    public B0 getThemedReactContext() {
        return (B0) getContext();
    }

    @Override // android.webkit.WebView
    public WebChromeClient getWebChromeClient() {
        return this.f8588r;
    }

    protected void h(String str) {
        evaluateJavascript(str, null);
    }

    public void j(String str, String str2) {
        getThemedReactContext();
        if (this.f8581k != null) {
            post(new c(this, str2, str));
            return;
        }
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putString("data", str);
        if (this.f8580j != null) {
            e(writableMapCreateMap);
        } else {
            g(this, new C0540g(q.a(this), writableMapCreateMap));
        }
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostDestroy() {
        c();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostPause() {
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostResume() {
    }

    @Override // android.webkit.WebView, android.view.View
    protected void onScrollChanged(int i3, int i4, int i5, int i6) {
        super.onScrollChanged(i3, i4, i5, i6);
        if (this.f8584n) {
            if (this.f8583m == null) {
                this.f8583m = new com.facebook.react.views.scroll.c();
            }
            if (this.f8583m.c(i3, i4)) {
                g(this, com.facebook.react.views.scroll.k.y(q.a(this), com.facebook.react.views.scroll.l.f8017e, i3, i4, this.f8583m.a(), this.f8583m.b(), computeHorizontalScrollRange(), computeVerticalScrollRange(), getWidth(), getHeight()));
            }
        }
    }

    @Override // android.webkit.WebView, android.view.View
    protected void onSizeChanged(int i3, int i4, int i5, int i6) {
        super.onSizeChanged(i3, i4, i5, i6);
        if (this.f8582l) {
            g(this, new O1.c(q.a(this), i3, i4));
        }
    }

    @Override // android.webkit.WebView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (this.f8585o) {
            requestDisallowInterceptTouchEvent(true);
        }
        return super.onTouchEvent(motionEvent);
    }

    public void setBasicAuthCredential(com.reactnativecommunity.webview.a aVar) {
        this.f8581k.c(aVar);
    }

    public void setHasScrollEvent(boolean z3) {
        this.f8584n = z3;
    }

    public void setIgnoreErrFailedForThisURL(String str) {
        this.f8581k.d(str);
    }

    public void setInjectedJavaScriptObject(String str) {
        this.f8589s = str;
        i();
    }

    public void setMenuCustomItems(List<Map<String, String>> list) {
        this.f8587q = list;
    }

    public void setMessagingEnabled(boolean z3) {
        if (this.f8578h == z3) {
            return;
        }
        this.f8578h = z3;
        if (z3) {
            d(this);
        }
    }

    public void setNestedScrollEnabled(boolean z3) {
        this.f8585o = z3;
    }

    public void setSendContentSizeChangeEvents(boolean z3) {
        this.f8582l = z3;
    }

    @Override // android.webkit.WebView
    public void setWebChromeClient(WebChromeClient webChromeClient) {
        this.f8588r = webChromeClient;
        super.setWebChromeClient(webChromeClient);
        if (webChromeClient instanceof com.reactnativecommunity.webview.c) {
            ((com.reactnativecommunity.webview.c) webChromeClient).h(this.f8586p);
        }
    }

    @Override // android.webkit.WebView
    public void setWebViewClient(WebViewClient webViewClient) {
        super.setWebViewClient(webViewClient);
        if (webViewClient instanceof h) {
            h hVar = (h) webViewClient;
            this.f8581k = hVar;
            hVar.e(this.f8586p);
        }
    }

    @Override // android.view.View
    public ActionMode startActionMode(ActionMode.Callback callback, int i3) {
        return this.f8587q == null ? super.startActionMode(callback, i3) : super.startActionMode(new a(callback), i3);
    }
}
