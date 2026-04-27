package com.facebook.react.uimanager;

import android.widget.ImageView;
import d1.AbstractC0508d;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
abstract class J0 {
    static Map a() {
        return AbstractC0508d.a().b("topChange", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onChange", "captured", "onChangeCapture"))).b("topSelect", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onSelect", "captured", "onSelectCapture"))).b(O1.s.b(O1.s.f2137d), AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onTouchStart", "captured", "onTouchStartCapture"))).b(O1.s.b(O1.s.f2139f), AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onTouchMove", "captured", "onTouchMoveCapture"))).b(O1.s.b(O1.s.f2138e), AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onTouchEnd", "captured", "onTouchEndCapture"))).b(O1.s.b(O1.s.f2140g), AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onTouchCancel", "captured", "onTouchCancelCapture"))).a();
    }

    public static Map b() {
        HashMap mapB = AbstractC0508d.b();
        mapB.put("UIView", AbstractC0508d.d("ContentMode", AbstractC0508d.f("ScaleAspectFit", Integer.valueOf(ImageView.ScaleType.FIT_CENTER.ordinal()), "ScaleAspectFill", Integer.valueOf(ImageView.ScaleType.CENTER_CROP.ordinal()), "ScaleAspectCenter", Integer.valueOf(ImageView.ScaleType.CENTER_INSIDE.ordinal()))));
        mapB.put("StyleConstants", AbstractC0508d.d("PointerEventsValues", AbstractC0508d.g("none", Integer.valueOf(EnumC0446g0.f7606c.ordinal()), "boxNone", Integer.valueOf(EnumC0446g0.f7607d.ordinal()), "boxOnly", Integer.valueOf(EnumC0446g0.f7608e.ordinal()), "unspecified", Integer.valueOf(EnumC0446g0.f7609f.ordinal()))));
        mapB.put("AccessibilityEventTypes", AbstractC0508d.f("typeWindowStateChanged", 32, "typeViewFocused", 8, "typeViewClicked", 1));
        return mapB;
    }

    static Map c() {
        return AbstractC0508d.a().b("topContentSizeChange", AbstractC0508d.d("registrationName", "onContentSizeChange")).b("topLayout", AbstractC0508d.d("registrationName", "onLayout")).b("topLoadingError", AbstractC0508d.d("registrationName", "onLoadingError")).b("topLoadingFinish", AbstractC0508d.d("registrationName", "onLoadingFinish")).b("topLoadingStart", AbstractC0508d.d("registrationName", "onLoadingStart")).b("topSelectionChange", AbstractC0508d.d("registrationName", "onSelectionChange")).b("topMessage", AbstractC0508d.d("registrationName", "onMessage")).b("topScrollBeginDrag", AbstractC0508d.d("registrationName", "onScrollBeginDrag")).b("topScrollEndDrag", AbstractC0508d.d("registrationName", "onScrollEndDrag")).b("topScroll", AbstractC0508d.d("registrationName", "onScroll")).b("topMomentumScrollBegin", AbstractC0508d.d("registrationName", "onMomentumScrollBegin")).b("topMomentumScrollEnd", AbstractC0508d.d("registrationName", "onMomentumScrollEnd")).a();
    }
}
