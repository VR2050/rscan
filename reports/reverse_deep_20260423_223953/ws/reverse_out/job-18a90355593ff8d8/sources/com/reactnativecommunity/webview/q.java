package com.reactnativecommunity.webview;

import android.content.Context;
import android.view.View;
import android.webkit.WebView;
import android.widget.FrameLayout;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class q extends FrameLayout {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f8668c = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final e f8669b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final int a(WebView webView) {
            t2.j.f(webView, "webView");
            Object parent = webView.getParent();
            View view = parent instanceof View ? (View) parent : null;
            if (view != null) {
                return view.getId();
            }
            return -1;
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(Context context, e eVar) {
        super(context);
        t2.j.f(context, "context");
        t2.j.f(eVar, "webView");
        eVar.setBackgroundColor(0);
        addView(eVar);
        View childAt = getChildAt(0);
        t2.j.d(childAt, "null cannot be cast to non-null type com.reactnativecommunity.webview.RNCWebView");
        this.f8669b = (e) childAt;
    }

    public static final int a(WebView webView) {
        return f8668c.a(webView);
    }

    public final e getWebView() {
        return this.f8669b;
    }
}
