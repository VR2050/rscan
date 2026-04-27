package com.facebook.react.views.view;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.view.View;
import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.DynamicFromObject;
import com.facebook.react.bridge.JSApplicationIllegalArgumentException;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.EnumC0446g0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.uimanager.events.EventDispatcher;
import i2.D;
import java.util.ArrayList;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import q1.C0655b;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactViewManager.REACT_CLASS)
public class ReactViewManager extends ReactClippingViewManager<g> {
    private static final int CMD_HOTSPOT_UPDATE = 1;
    private static final int CMD_SET_PRESSED = 2;
    private static final String HOTSPOT_UPDATE_KEY = "hotspotUpdate";
    public static final String REACT_CLASS = "RCTView";
    public static final a Companion = new a(null);
    private static final int[] SPACING_TYPES = {8, 0, 2, 1, 3, 4, 5, 9, 10, 11};

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f8283a;

        static {
            int[] iArr = new int[ReadableType.values().length];
            try {
                iArr[ReadableType.Map.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[ReadableType.Number.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[ReadableType.Null.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            f8283a = iArr;
        }
    }

    public ReactViewManager() {
        if (C0655b.l()) {
            setupViewRecycling();
        }
    }

    private final void handleHotspotUpdate(g gVar, ReadableArray readableArray) {
        if (readableArray == null || readableArray.size() != 2) {
            throw new JSApplicationIllegalArgumentException("Illegal number of arguments for 'updateHotspot' command");
        }
        C0444f0 c0444f0 = C0444f0.f7603a;
        gVar.drawableHotspotChanged(c0444f0.a(readableArray.getDouble(0)), c0444f0.a(readableArray.getDouble(1)));
    }

    private final void handleSetPressed(g gVar, ReadableArray readableArray) {
        if (readableArray == null || readableArray.size() != 1) {
            throw new JSApplicationIllegalArgumentException("Illegal number of arguments for 'setPressed' command");
        }
        gVar.setPressed(readableArray.getBoolean(0));
    }

    private final int px(ReadableMap readableMap, String str) {
        if (readableMap.hasKey(str)) {
            return (int) C0444f0.f7603a.a(readableMap.getDouble(str));
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setFocusable$lambda$2(g gVar, View view) {
        Context context = gVar.getContext();
        t2.j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
        EventDispatcher eventDispatcherC = H0.c((ReactContext) context, gVar.getId());
        if (eventDispatcherC != null) {
            eventDispatcherC.g(new j(H0.e(gVar.getContext()), gVar.getId()));
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Integer> getCommandsMap() {
        return D.i(h2.n.a(HOTSPOT_UPDATE_KEY, 1), h2.n.a("setPressed", 2));
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @K1.a(defaultInt = -1, name = "nextFocusDown")
    public void nextFocusDown(g gVar, int i3) {
        t2.j.f(gVar, "view");
        gVar.setNextFocusDownId(i3);
    }

    @K1.a(defaultInt = -1, name = "nextFocusForward")
    public void nextFocusForward(g gVar, int i3) {
        t2.j.f(gVar, "view");
        gVar.setNextFocusForwardId(i3);
    }

    @K1.a(defaultInt = -1, name = "nextFocusLeft")
    public void nextFocusLeft(g gVar, int i3) {
        t2.j.f(gVar, "view");
        gVar.setNextFocusLeftId(i3);
    }

    @K1.a(defaultInt = -1, name = "nextFocusRight")
    public void nextFocusRight(g gVar, int i3) {
        t2.j.f(gVar, "view");
        gVar.setNextFocusRightId(i3);
    }

    @K1.a(defaultInt = -1, name = "nextFocusUp")
    public void nextFocusUp(g gVar, int i3) {
        t2.j.f(gVar, "view");
        gVar.setNextFocusUpId(i3);
    }

    @K1.a(name = "accessible")
    public void setAccessible(g gVar, boolean z3) {
        t2.j.f(gVar, "view");
        gVar.setFocusable(z3);
    }

    @K1.a(name = "backfaceVisibility")
    public void setBackfaceVisibility(g gVar, String str) {
        t2.j.f(gVar, "view");
        t2.j.f(str, "backfaceVisibility");
        gVar.setBackfaceVisibility(str);
    }

    @K1.a(customType = "BackgroundImage", name = "experimental_backgroundImage")
    public void setBackgroundImage(g gVar, ReadableArray readableArray) {
        t2.j.f(gVar, "view");
        if (L1.a.c(gVar) == 2) {
            if (readableArray == null || readableArray.size() <= 0) {
                C0433a.o(gVar, null);
                return;
            }
            ArrayList arrayList = new ArrayList(readableArray.size());
            int size = readableArray.size();
            for (int i3 = 0; i3 < size; i3++) {
                ReadableMap map = readableArray.getMap(i3);
                Context context = gVar.getContext();
                t2.j.e(context, "getContext(...)");
                arrayList.add(new Q1.a(map, context));
            }
            C0433a.o(gVar, arrayList);
        }
    }

    @K1.b(customType = "Color", names = {"borderColor", "borderLeftColor", "borderRightColor", "borderTopColor", "borderBottomColor", "borderStartColor", "borderEndColor", "borderBlockColor", "borderBlockEndColor", "borderBlockStartColor"})
    public void setBorderColor(g gVar, int i3, Integer num) {
        t2.j.f(gVar, "view");
        C0433a.p(gVar, Q1.n.f2477b.a(SPACING_TYPES[i3]), num);
    }

    @K1.b(names = {"borderRadius", "borderTopLeftRadius", "borderTopRightRadius", "borderBottomRightRadius", "borderBottomLeftRadius", "borderTopStartRadius", "borderTopEndRadius", "borderBottomStartRadius", "borderBottomEndRadius", "borderEndEndRadius", "borderEndStartRadius", "borderStartEndRadius", "borderStartStartRadius"})
    public void setBorderRadius(g gVar, int i3, Dynamic dynamic) {
        t2.j.f(gVar, "view");
        t2.j.f(dynamic, "rawBorderRadius");
        W wA = W.f7531c.a(dynamic);
        if (L1.a.c(gVar) != 2 && wA != null && wA.a() == X.f7536c) {
            wA = null;
        }
        C0433a.q(gVar, Q1.d.values()[i3], wA);
    }

    @K1.a(name = "borderStyle")
    public void setBorderStyle(g gVar, String str) {
        t2.j.f(gVar, "view");
        C0433a.r(gVar, str == null ? null : Q1.f.f2431b.a(str));
    }

    @K1.b(defaultFloat = Float.NaN, names = {"borderWidth", "borderLeftWidth", "borderRightWidth", "borderTopWidth", "borderBottomWidth", "borderStartWidth", "borderEndWidth"})
    public void setBorderWidth(g gVar, int i3, float f3) {
        t2.j.f(gVar, "view");
        C0433a.s(gVar, Q1.n.values()[i3], Float.valueOf(f3));
    }

    @K1.a(name = "collapsable")
    public void setCollapsable(g gVar, boolean z3) {
        t2.j.f(gVar, "view");
    }

    @K1.a(name = "collapsableChildren")
    public void setCollapsableChildren(g gVar, boolean z3) {
        t2.j.f(gVar, "view");
    }

    @K1.a(name = "focusable")
    public void setFocusable(final g gVar, boolean z3) {
        t2.j.f(gVar, "view");
        if (z3) {
            gVar.setOnClickListener(new View.OnClickListener() { // from class: com.facebook.react.views.view.i
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    ReactViewManager.setFocusable$lambda$2(gVar, view);
                }
            });
            gVar.setFocusable(true);
        } else {
            gVar.setOnClickListener(null);
            gVar.setClickable(false);
        }
    }

    @K1.a(name = "hitSlop")
    public void setHitSlop(g gVar, Dynamic dynamic) {
        t2.j.f(gVar, "view");
        t2.j.f(dynamic, "hitSlop");
        int i3 = b.f8283a[dynamic.getType().ordinal()];
        if (i3 == 1) {
            ReadableMap readableMapAsMap = dynamic.asMap();
            gVar.setHitSlopRect(new Rect(px(readableMapAsMap, "left"), px(readableMapAsMap, "top"), px(readableMapAsMap, "right"), px(readableMapAsMap, "bottom")));
            return;
        }
        if (i3 == 2) {
            int iA = (int) C0444f0.f7603a.a(dynamic.asDouble());
            gVar.setHitSlopRect(new Rect(iA, iA, iA, iA));
        } else {
            if (i3 == 3) {
                gVar.setHitSlopRect(null);
                return;
            }
            Y.a.I("ReactNative", "Invalid type for 'hitSlop' value " + dynamic.getType());
            gVar.setHitSlopRect(null);
        }
    }

    @K1.a(name = "nativeBackgroundAndroid")
    public void setNativeBackground(g gVar, ReadableMap readableMap) {
        Drawable drawableA;
        t2.j.f(gVar, "view");
        if (readableMap != null) {
            Context context = gVar.getContext();
            t2.j.e(context, "getContext(...)");
            drawableA = f.a(context, readableMap);
        } else {
            drawableA = null;
        }
        C0433a.v(gVar, drawableA);
    }

    @K1.a(name = "nativeForegroundAndroid")
    public void setNativeForeground(g gVar, ReadableMap readableMap) {
        Drawable drawableA;
        t2.j.f(gVar, "view");
        if (readableMap != null) {
            Context context = gVar.getContext();
            t2.j.e(context, "getContext(...)");
            drawableA = f.a(context, readableMap);
        } else {
            drawableA = null;
        }
        gVar.setForeground(drawableA);
    }

    @K1.a(name = "needsOffscreenAlphaCompositing")
    public void setNeedsOffscreenAlphaCompositing(g gVar, boolean z3) {
        t2.j.f(gVar, "view");
        gVar.setNeedsOffscreenAlphaCompositing(z3);
    }

    @K1.a(name = "overflow")
    public void setOverflow(g gVar, String str) {
        t2.j.f(gVar, "view");
        gVar.setOverflow(str);
    }

    @K1.a(name = "pointerEvents")
    public void setPointerEvents(g gVar, String str) {
        t2.j.f(gVar, "view");
        gVar.setPointerEvents(EnumC0446g0.f7605b.c(str));
    }

    @K1.a(name = "hasTVPreferredFocus")
    public void setTVPreferredFocus(g gVar, boolean z3) {
        t2.j.f(gVar, "view");
        if (z3) {
            gVar.setFocusable(true);
            gVar.setFocusableInTouchMode(true);
            gVar.requestFocus();
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public g createViewInstance(B0 b02) {
        t2.j.f(b02, "context");
        return new g(b02);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public g prepareToRecycleView(B0 b02, g gVar) {
        t2.j.f(b02, "reactContext");
        t2.j.f(gVar, "view");
        g gVar2 = (g) super.prepareToRecycleView(b02, gVar);
        if (gVar2 != null) {
            gVar2.s();
        }
        return gVar;
    }

    @Override // com.facebook.react.uimanager.BaseViewManager
    public void setOpacity(g gVar, float f3) {
        t2.j.f(gVar, "view");
        gVar.setOpacityIfPossible(f3);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager
    public void setTransformProperty(g gVar, ReadableArray readableArray, ReadableArray readableArray2) {
        t2.j.f(gVar, "view");
        super.setTransformProperty(gVar, readableArray, readableArray2);
        gVar.x();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(g gVar, int i3, ReadableArray readableArray) {
        t2.j.f(gVar, "root");
        if (i3 == 1) {
            handleHotspotUpdate(gVar, readableArray);
        } else {
            if (i3 != 2) {
                return;
            }
            handleSetPressed(gVar, readableArray);
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(g gVar, String str, ReadableArray readableArray) {
        t2.j.f(gVar, "root");
        t2.j.f(str, "commandId");
        if (t2.j.b(str, HOTSPOT_UPDATE_KEY)) {
            handleHotspotUpdate(gVar, readableArray);
        } else if (t2.j.b(str, "setPressed")) {
            handleSetPressed(gVar, readableArray);
        }
    }

    public void setBorderRadius(g gVar, int i3, float f3) {
        t2.j.f(gVar, "view");
        setBorderRadius(gVar, i3, new DynamicFromObject(Float.valueOf(f3)));
    }
}
