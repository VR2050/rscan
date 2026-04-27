package com.facebook.react.views.scroll;

import Q1.n;
import android.view.View;
import androidx.core.view.V;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.RetryableMountingLayerException;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.C0469s0;
import com.facebook.react.uimanager.EnumC0446g0;
import com.facebook.react.uimanager.ViewGroupManager;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.views.scroll.b;
import com.facebook.react.views.scroll.i;
import d1.AbstractC0508d;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactScrollViewManager.REACT_CLASS)
public class ReactScrollViewManager extends ViewGroupManager<g> implements i.b {
    public static final String REACT_CLASS = "RCTScrollView";
    private static final int[] SPACING_TYPES = {8, 0, 2, 1, 3};
    private a mFpsListener;

    public ReactScrollViewManager() {
        this(null);
    }

    public static Map<String, Object> createExportedCustomDirectEventTypeConstants() {
        return AbstractC0508d.a().b(l.b(l.f8017e), AbstractC0508d.d("registrationName", "onScroll")).b(l.b(l.f8015c), AbstractC0508d.d("registrationName", "onScrollBeginDrag")).b(l.b(l.f8016d), AbstractC0508d.d("registrationName", "onScrollEndDrag")).b(l.b(l.f8018f), AbstractC0508d.d("registrationName", "onMomentumScrollBegin")).b(l.b(l.f8019g), AbstractC0508d.d("registrationName", "onMomentumScrollEnd")).a();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Integer> getCommandsMap() {
        return i.a();
    }

    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedCustomDirectEventTypeConstants() {
        Map<String, Object> exportedCustomDirectEventTypeConstants = super.getExportedCustomDirectEventTypeConstants();
        if (exportedCustomDirectEventTypeConstants == null) {
            exportedCustomDirectEventTypeConstants = new HashMap<>();
        }
        exportedCustomDirectEventTypeConstants.putAll(createExportedCustomDirectEventTypeConstants());
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager, com.facebook.react.uimanager.N
    public /* bridge */ /* synthetic */ void removeAllViews(View view) {
        super.removeAllViews(view);
    }

    @K1.b(customType = "Color", names = {"borderColor", "borderLeftColor", "borderRightColor", "borderTopColor", "borderBottomColor"})
    public void setBorderColor(g gVar, int i3, Integer num) {
        C0433a.p(gVar, n.f2478c, num);
    }

    @K1.b(defaultFloat = Float.NaN, names = {"borderRadius", "borderTopLeftRadius", "borderTopRightRadius", "borderBottomRightRadius", "borderBottomLeftRadius"})
    public void setBorderRadius(g gVar, int i3, float f3) {
        C0433a.q(gVar, Q1.d.values()[i3], Float.isNaN(f3) ? null : new W(f3, X.f7535b));
    }

    @K1.a(name = "borderStyle")
    public void setBorderStyle(g gVar, String str) {
        C0433a.r(gVar, str == null ? null : Q1.f.b(str));
    }

    @K1.b(defaultFloat = Float.NaN, names = {"borderWidth", "borderLeftWidth", "borderRightWidth", "borderTopWidth", "borderBottomWidth"})
    public void setBorderWidth(g gVar, int i3, float f3) {
        C0433a.s(gVar, n.values()[i3], Float.valueOf(f3));
    }

    @K1.a(customType = "Color", defaultInt = WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY, name = "endFillColor")
    public void setBottomFillColor(g gVar, int i3) {
        gVar.setEndFillColor(i3);
    }

    @K1.a(customType = "Point", name = "contentOffset")
    public void setContentOffset(g gVar, ReadableMap readableMap) {
        gVar.setContentOffset(readableMap);
    }

    @K1.a(name = "decelerationRate")
    public void setDecelerationRate(g gVar, float f3) {
        gVar.setDecelerationRate(f3);
    }

    @K1.a(name = "disableIntervalMomentum")
    public void setDisableIntervalMomentum(g gVar, boolean z3) {
        gVar.setDisableIntervalMomentum(z3);
    }

    @K1.a(name = "fadingEdgeLength")
    public void setFadingEdgeLength(g gVar, int i3) {
        if (i3 > 0) {
            gVar.setVerticalFadingEdgeEnabled(true);
            gVar.setFadingEdgeLength(i3);
        } else {
            gVar.setVerticalFadingEdgeEnabled(false);
            gVar.setFadingEdgeLength(0);
        }
    }

    @K1.a(name = "horizontal")
    public void setHorizontal(g gVar, boolean z3) {
    }

    @K1.a(name = "isInvertedVirtualizedList")
    public void setIsInvertedVirtualizedList(g gVar, boolean z3) {
        if (z3) {
            gVar.setVerticalScrollbarPosition(1);
        } else {
            gVar.setVerticalScrollbarPosition(0);
        }
    }

    @K1.a(name = "maintainVisibleContentPosition")
    public void setMaintainVisibleContentPosition(g gVar, ReadableMap readableMap) {
        if (readableMap != null) {
            gVar.setMaintainVisibleContentPosition(b.C0118b.a(readableMap));
        } else {
            gVar.setMaintainVisibleContentPosition(null);
        }
    }

    @K1.a(name = "nestedScrollEnabled")
    public void setNestedScrollEnabled(g gVar, boolean z3) {
        V.h0(gVar, z3);
    }

    @K1.a(name = "overScrollMode")
    public void setOverScrollMode(g gVar, String str) {
        gVar.setOverScrollMode(j.n(str));
    }

    @K1.a(name = "overflow")
    public void setOverflow(g gVar, String str) {
        gVar.setOverflow(str);
    }

    @K1.a(name = "pagingEnabled")
    public void setPagingEnabled(g gVar, boolean z3) {
        gVar.setPagingEnabled(z3);
    }

    @K1.a(name = "persistentScrollbar")
    public void setPersistentScrollbar(g gVar, boolean z3) {
        gVar.setScrollbarFadingEnabled(!z3);
    }

    @K1.a(name = "pointerEvents")
    public void setPointerEvents(g gVar, String str) {
        gVar.setPointerEvents(EnumC0446g0.d(str));
    }

    @K1.a(name = "removeClippedSubviews")
    public void setRemoveClippedSubviews(g gVar, boolean z3) {
        gVar.setRemoveClippedSubviews(z3);
    }

    @K1.a(defaultBoolean = true, name = "scrollEnabled")
    public void setScrollEnabled(g gVar, boolean z3) {
        gVar.setScrollEnabled(z3);
        gVar.setFocusable(z3);
    }

    @K1.a(name = "scrollEventThrottle")
    public void setScrollEventThrottle(g gVar, int i3) {
        gVar.setScrollEventThrottle(i3);
    }

    @K1.a(name = "scrollPerfTag")
    public void setScrollPerfTag(g gVar, String str) {
        gVar.setScrollPerfTag(str);
    }

    @K1.a(name = "sendMomentumEvents")
    public void setSendMomentumEvents(g gVar, boolean z3) {
        gVar.setSendMomentumEvents(z3);
    }

    @K1.a(defaultBoolean = true, name = "showsVerticalScrollIndicator")
    public void setShowsVerticalScrollIndicator(g gVar, boolean z3) {
        gVar.setVerticalScrollBarEnabled(z3);
    }

    @K1.a(name = "snapToAlignment")
    public void setSnapToAlignment(g gVar, String str) {
        gVar.setSnapToAlignment(j.o(str));
    }

    @K1.a(name = "snapToEnd")
    public void setSnapToEnd(g gVar, boolean z3) {
        gVar.setSnapToEnd(z3);
    }

    @K1.a(name = "snapToInterval")
    public void setSnapToInterval(g gVar, float f3) {
        gVar.setSnapInterval((int) (f3 * C0444f0.c()));
    }

    @K1.a(name = "snapToOffsets")
    public void setSnapToOffsets(g gVar, ReadableArray readableArray) {
        if (readableArray == null || readableArray.size() == 0) {
            gVar.setSnapOffsets(null);
            return;
        }
        float fC = C0444f0.c();
        ArrayList arrayList = new ArrayList();
        for (int i3 = 0; i3 < readableArray.size(); i3++) {
            arrayList.add(Integer.valueOf((int) (readableArray.getDouble(i3) * ((double) fC))));
        }
        gVar.setSnapOffsets(arrayList);
    }

    @K1.a(name = "snapToStart")
    public void setSnapToStart(g gVar, boolean z3) {
        gVar.setSnapToStart(z3);
    }

    public ReactScrollViewManager(a aVar) {
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public g createViewInstance(B0 b02) {
        return new g(b02, null);
    }

    @Override // com.facebook.react.views.scroll.i.b
    public void flashScrollIndicators(g gVar) {
        gVar.t();
    }

    @Override // com.facebook.react.views.scroll.i.b
    public void scrollTo(g gVar, i.c cVar) {
        gVar.o();
        if (cVar.f7983c) {
            gVar.f(cVar.f7981a, cVar.f7982b);
        } else {
            gVar.scrollTo(cVar.f7981a, cVar.f7982b);
        }
    }

    @Override // com.facebook.react.views.scroll.i.b
    public void scrollToEnd(g gVar, i.d dVar) {
        View childAt = gVar.getChildAt(0);
        if (childAt == null) {
            throw new RetryableMountingLayerException("scrollToEnd called on ScrollView without child");
        }
        int height = childAt.getHeight() + gVar.getPaddingBottom();
        gVar.o();
        if (dVar.f7984a) {
            gVar.f(gVar.getScrollX(), height);
        } else {
            gVar.scrollTo(gVar.getScrollX(), height);
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Object updateState(g gVar, C0469s0 c0469s0, A0 a02) {
        gVar.setStateWrapper(a02);
        return null;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(g gVar, int i3, ReadableArray readableArray) {
        i.b(this, gVar, i3, readableArray);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(g gVar, String str, ReadableArray readableArray) {
        i.c(this, gVar, str, readableArray);
    }
}
