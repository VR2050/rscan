package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.views.image.ReactImageManager;
import com.facebook.react.views.modal.ReactModalHostManager;
import com.facebook.react.views.progressbar.ReactProgressBarViewManager;
import com.facebook.react.views.scroll.ReactScrollViewManager;
import com.facebook.react.views.text.ReactRawTextManager;
import com.facebook.react.views.text.ReactTextViewManager;
import com.facebook.react.views.view.ReactViewManager;
import h2.n;
import i2.D;
import java.util.Map;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final f f6982a = new f();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Map f6983b = D.h(n.a("View", ReactViewManager.REACT_CLASS), n.a("Image", ReactImageManager.REACT_CLASS), n.a("ScrollView", ReactScrollViewManager.REACT_CLASS), n.a("Slider", "RCTSlider"), n.a("ModalHostView", ReactModalHostManager.REACT_CLASS), n.a("Paragraph", ReactTextViewManager.REACT_CLASS), n.a("Text", ReactTextViewManager.REACT_CLASS), n.a("RawText", ReactRawTextManager.REACT_CLASS), n.a("ActivityIndicatorView", ReactProgressBarViewManager.REACT_CLASS), n.a("ShimmeringView", "RKShimmeringView"), n.a("TemplateView", "RCTTemplateView"), n.a("AxialGradientView", "RCTAxialGradientView"), n.a("Video", "RCTVideo"), n.a("Map", "RCTMap"), n.a("WebView", "RCTWebView"), n.a("Keyframes", "RCTKeyframes"), n.a("ImpressionTrackingView", "RCTImpressionTrackingView"));

    private f() {
    }

    public static final String a(String str) {
        j.f(str, "componentName");
        String str2 = (String) f6983b.get(str);
        return str2 == null ? str : str2;
    }
}
