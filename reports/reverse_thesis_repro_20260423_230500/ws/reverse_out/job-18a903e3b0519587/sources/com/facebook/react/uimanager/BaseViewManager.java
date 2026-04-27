package com.facebook.react.uimanager;

import O1.o;
import android.graphics.Paint;
import android.os.Build;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewParent;
import c1.AbstractC0339k;
import c1.AbstractC0342n;
import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.uimanager.C0448h0;
import com.facebook.react.uimanager.U;
import com.facebook.react.uimanager.Y;
import d1.AbstractC0508d;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public abstract class BaseViewManager<T extends View, C extends U> extends ViewManager<T, C> implements View.OnLayoutChangeListener {
    private static final int PERSPECTIVE_ARRAY_INVERTED_CAMERA_DISTANCE_INDEX = 2;
    private static final String STATE_BUSY = "busy";
    private static final String STATE_CHECKED = "checked";
    private static final String STATE_EXPANDED = "expanded";
    private static final String STATE_MIXED = "mixed";
    private static final float CAMERA_DISTANCE_NORMALIZATION_MULTIPLIER = (float) Math.sqrt(5.0d);
    private static final Y.a sMatrixDecompositionContext = new Y.a();
    private static final double[] sTransformDecompositionArray = new double[16];

    private static class a {
        public static void a(View view, ReadableArray readableArray, Boolean bool) {
            Paint paint;
            int i3 = Build.VERSION.SDK_INT;
            if (i3 >= 31) {
                view.setRenderEffect(null);
            }
            if (readableArray == null) {
                paint = null;
            } else if (K.t(readableArray)) {
                paint = new Paint();
                paint.setColorFilter(K.v(readableArray));
            } else {
                if (i3 >= 31) {
                    view.setRenderEffect(K.w(readableArray));
                }
                paint = null;
            }
            if (paint == null) {
                view.setLayerType((bool == null || !bool.booleanValue()) ? 0 : 2, null);
            } else {
                view.setLayerType(2, paint);
            }
        }
    }

    public BaseViewManager() {
        super(null);
    }

    private void logUnsupportedPropertyWarning(String str) {
        Y.a.K("ReactNative", "%s doesn't support property '%s'", getName(), str);
    }

    private static float sanitizeFloatPropertyValue(float f3) {
        if (f3 >= -3.4028235E38f && f3 <= Float.MAX_VALUE) {
            return f3;
        }
        if (f3 < -3.4028235E38f || f3 == Float.NEGATIVE_INFINITY) {
            return -3.4028235E38f;
        }
        if (f3 > Float.MAX_VALUE || f3 == Float.POSITIVE_INFINITY) {
            return Float.MAX_VALUE;
        }
        if (Float.isNaN(f3)) {
            return 0.0f;
        }
        throw new IllegalStateException("Invalid float property value: " + f3);
    }

    private static void setPointerEventsFlag(View view, o.a aVar, boolean z3) {
        Integer num = (Integer) view.getTag(AbstractC0339k.f5595s);
        int iIntValue = num != null ? num.intValue() : 0;
        int iOrdinal = 1 << aVar.ordinal();
        view.setTag(AbstractC0339k.f5595s, Integer.valueOf(z3 ? iOrdinal | iIntValue : (~iOrdinal) & iIntValue));
    }

    private void updateViewContentDescription(T t3) {
        Dynamic dynamic;
        String str = (String) t3.getTag(AbstractC0339k.f5581e);
        ReadableMap readableMap = (ReadableMap) t3.getTag(AbstractC0339k.f5584h);
        ArrayList arrayList = new ArrayList();
        ReadableMap readableMap2 = (ReadableMap) t3.getTag(AbstractC0339k.f5586j);
        if (str != null) {
            arrayList.add(str);
        }
        if (readableMap != null) {
            ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = readableMap.keySetIterator();
            while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
                String strNextKey = readableMapKeySetIteratorKeySetIterator.nextKey();
                Dynamic dynamic2 = readableMap.getDynamic(strNextKey);
                if (strNextKey.equals(STATE_CHECKED) && dynamic2.getType() == ReadableType.String && dynamic2.asString().equals(STATE_MIXED)) {
                    arrayList.add(t3.getContext().getString(AbstractC0342n.f5616F));
                } else if (strNextKey.equals(STATE_BUSY) && dynamic2.getType() == ReadableType.Boolean && dynamic2.asBoolean()) {
                    arrayList.add(t3.getContext().getString(AbstractC0342n.f5615E));
                }
            }
        }
        if (readableMap2 != null && readableMap2.hasKey("text") && (dynamic = readableMap2.getDynamic("text")) != null && dynamic.getType() == ReadableType.String) {
            arrayList.add(dynamic.asString());
        }
        if (arrayList.isEmpty()) {
            return;
        }
        t3.setContentDescription(TextUtils.join(", ", arrayList));
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedCustomBubblingEventTypeConstants() {
        Map<String, Object> exportedCustomDirectEventTypeConstants = super.getExportedCustomDirectEventTypeConstants();
        if (exportedCustomDirectEventTypeConstants == null) {
            exportedCustomDirectEventTypeConstants = new HashMap<>();
        }
        AbstractC0508d.a aVarB = AbstractC0508d.a().b("topPointerCancel", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onPointerCancel", "captured", "onPointerCancelCapture"))).b("topPointerDown", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onPointerDown", "captured", "onPointerDownCapture")));
        Boolean bool = Boolean.TRUE;
        exportedCustomDirectEventTypeConstants.putAll(aVarB.b("topPointerEnter", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.f("bubbled", "onPointerEnter", "captured", "onPointerEnterCapture", "skipBubbling", bool))).b("topPointerLeave", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.f("bubbled", "onPointerLeave", "captured", "onPointerLeaveCapture", "skipBubbling", bool))).b("topPointerMove", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onPointerMove", "captured", "onPointerMoveCapture"))).b("topPointerUp", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onPointerUp", "captured", "onPointerUpCapture"))).b("topPointerOut", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onPointerOut", "captured", "onPointerOutCapture"))).b("topPointerOver", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onPointerOver", "captured", "onPointerOverCapture"))).b("topClick", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onClick", "captured", "onClickCapture"))).a());
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedCustomDirectEventTypeConstants() {
        Map<String, Object> exportedCustomDirectEventTypeConstants = super.getExportedCustomDirectEventTypeConstants();
        if (exportedCustomDirectEventTypeConstants == null) {
            exportedCustomDirectEventTypeConstants = new HashMap<>();
        }
        exportedCustomDirectEventTypeConstants.putAll(AbstractC0508d.a().b("topAccessibilityAction", AbstractC0508d.d("registrationName", "onAccessibilityAction")).a());
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    protected void onAfterUpdateTransaction(T t3) {
        super.onAfterUpdateTransaction(t3);
        updateViewAccessibility(t3);
        Boolean bool = (Boolean) t3.getTag(AbstractC0339k.f5592p);
        if (bool != null && bool.booleanValue()) {
            t3.addOnLayoutChangeListener(this);
            setTransformProperty(t3, (ReadableArray) t3.getTag(AbstractC0339k.f5572A), (ReadableArray) t3.getTag(AbstractC0339k.f5573B));
            t3.setTag(AbstractC0339k.f5592p, Boolean.FALSE);
        }
        a.a(t3, (ReadableArray) t3.getTag(AbstractC0339k.f5590n), (Boolean) t3.getTag(AbstractC0339k.f5574C));
    }

    @Override // android.view.View.OnLayoutChangeListener
    public void onLayoutChange(View view, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10) {
        int i11 = i9 - i7;
        int i12 = i5 - i3;
        if (i6 - i4 == i10 - i8 && i12 == i11) {
            return;
        }
        ReadableArray readableArray = (ReadableArray) view.getTag(AbstractC0339k.f5573B);
        ReadableArray readableArray2 = (ReadableArray) view.getTag(AbstractC0339k.f5572A);
        if (readableArray2 == null && readableArray == null) {
            return;
        }
        setTransformProperty(view, readableArray2, readableArray);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    protected T prepareToRecycleView(B0 b02, T t3) {
        t3.setTag(null);
        t3.setTag(AbstractC0339k.f5595s, null);
        t3.setTag(AbstractC0339k.f5596t, null);
        t3.setTag(AbstractC0339k.f5576E, null);
        t3.setTag(AbstractC0339k.f5593q, null);
        t3.setTag(AbstractC0339k.f5581e, null);
        t3.setTag(AbstractC0339k.f5580d, null);
        t3.setTag(AbstractC0339k.f5583g, null);
        t3.setTag(AbstractC0339k.f5584h, null);
        t3.setTag(AbstractC0339k.f5577a, null);
        t3.setTag(AbstractC0339k.f5586j, null);
        t3.setTag(AbstractC0339k.f5585i, null);
        t3.setTag(AbstractC0339k.f5575D, null);
        setTransformProperty(t3, null, null);
        int i3 = Build.VERSION.SDK_INT;
        if (i3 < 28) {
            return null;
        }
        t3.resetPivot();
        t3.setTop(0);
        t3.setBottom(0);
        t3.setLeft(0);
        t3.setRight(0);
        t3.setElevation(0.0f);
        if (i3 >= 29) {
            t3.setAnimationMatrix(null);
        }
        t3.setTag(AbstractC0339k.f5572A, null);
        t3.setTag(AbstractC0339k.f5573B, null);
        t3.setTag(AbstractC0339k.f5592p, null);
        t3.removeOnLayoutChangeListener(this);
        t3.setTag(AbstractC0339k.f5574C, null);
        t3.setTag(AbstractC0339k.f5590n, null);
        t3.setTag(AbstractC0339k.f5594r, null);
        a.a(t3, null, null);
        if (i3 >= 28) {
            t3.setOutlineAmbientShadowColor(-16777216);
            t3.setOutlineSpotShadowColor(-16777216);
        }
        t3.setNextFocusDownId(-1);
        t3.setNextFocusForwardId(-1);
        t3.setNextFocusRightId(-1);
        t3.setNextFocusUpId(-1);
        t3.setFocusable(false);
        t3.setFocusableInTouchMode(false);
        t3.setElevation(0.0f);
        t3.setAlpha(1.0f);
        setPadding(t3, 0, 0, 0, 0);
        t3.setForeground(null);
        return t3;
    }

    @K1.a(name = "accessibilityActions")
    public void setAccessibilityActions(T t3, ReadableArray readableArray) {
        if (readableArray == null) {
            return;
        }
        t3.setTag(AbstractC0339k.f5577a, readableArray);
    }

    @K1.a(name = "accessibilityCollection")
    public void setAccessibilityCollection(T t3, ReadableMap readableMap) {
        t3.setTag(AbstractC0339k.f5578b, readableMap);
    }

    @K1.a(name = "accessibilityCollectionItem")
    public void setAccessibilityCollectionItem(T t3, ReadableMap readableMap) {
        t3.setTag(AbstractC0339k.f5579c, readableMap);
    }

    @K1.a(name = "accessibilityHint")
    public void setAccessibilityHint(T t3, String str) {
        t3.setTag(AbstractC0339k.f5580d, str);
        updateViewContentDescription(t3);
    }

    @K1.a(name = "accessibilityLabel")
    public void setAccessibilityLabel(T t3, String str) {
        t3.setTag(AbstractC0339k.f5581e, str);
        updateViewContentDescription(t3);
    }

    @K1.a(name = "accessibilityLabelledBy")
    public void setAccessibilityLabelledBy(T t3, Dynamic dynamic) {
        if (dynamic.isNull()) {
            return;
        }
        if (dynamic.getType() == ReadableType.String) {
            t3.setTag(AbstractC0339k.f5593q, dynamic.asString());
        } else if (dynamic.getType() == ReadableType.Array) {
            t3.setTag(AbstractC0339k.f5593q, dynamic.asArray().getString(0));
        }
    }

    @K1.a(name = "accessibilityLiveRegion")
    public void setAccessibilityLiveRegion(T t3, String str) {
        if (str == null || str.equals("none")) {
            androidx.core.view.V.Z(t3, 0);
        } else if (str.equals("polite")) {
            androidx.core.view.V.Z(t3, 1);
        } else if (str.equals("assertive")) {
            androidx.core.view.V.Z(t3, 2);
        }
    }

    @K1.a(name = "accessibilityRole")
    public void setAccessibilityRole(T t3, String str) {
        if (str == null) {
            t3.setTag(AbstractC0339k.f5583g, null);
        } else {
            t3.setTag(AbstractC0339k.f5583g, C0448h0.d.c(str));
        }
    }

    @K1.a(name = "accessibilityValue")
    public void setAccessibilityValue(T t3, ReadableMap readableMap) {
        if (readableMap == null) {
            t3.setTag(AbstractC0339k.f5586j, null);
            t3.setContentDescription(null);
        } else {
            t3.setTag(AbstractC0339k.f5586j, readableMap);
            if (readableMap.hasKey("text")) {
                updateViewContentDescription(t3);
            }
        }
    }

    @K1.a(customType = "Color", defaultInt = WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY, name = "backgroundColor")
    public void setBackgroundColor(T t3, int i3) {
        C0433a.n(t3, Integer.valueOf(i3));
    }

    public void setBorderBottomLeftRadius(T t3, float f3) {
        logUnsupportedPropertyWarning("borderBottomLeftRadius");
    }

    public void setBorderBottomRightRadius(T t3, float f3) {
        logUnsupportedPropertyWarning("borderBottomRightRadius");
    }

    public void setBorderRadius(T t3, float f3) {
        logUnsupportedPropertyWarning("borderRadius");
    }

    public void setBorderTopLeftRadius(T t3, float f3) {
        logUnsupportedPropertyWarning("borderTopLeftRadius");
    }

    public void setBorderTopRightRadius(T t3, float f3) {
        logUnsupportedPropertyWarning("borderTopRightRadius");
    }

    @K1.a(customType = "BoxShadow", name = "boxShadow")
    public void setBoxShadow(T t3, ReadableArray readableArray) {
        C0433a.t(t3, readableArray);
    }

    @K1.a(name = "onClick")
    public void setClick(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2107d, z3);
    }

    @K1.a(name = "onClickCapture")
    public void setClickCapture(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2108e, z3);
    }

    @K1.a(name = "elevation")
    public void setElevation(T t3, float f3) {
        androidx.core.view.V.e0(t3, C0444f0.h(f3));
    }

    @K1.a(customType = "Filter", name = "filter")
    public void setFilter(T t3, ReadableArray readableArray) {
        if (L1.a.c(t3) == 2) {
            t3.setTag(AbstractC0339k.f5590n, readableArray);
        }
    }

    @K1.a(name = "importantForAccessibility")
    public void setImportantForAccessibility(T t3, String str) {
        if (str == null || str.equals("auto")) {
            androidx.core.view.V.f0(t3, 0);
            return;
        }
        if (str.equals("yes")) {
            androidx.core.view.V.f0(t3, 1);
        } else if (str.equals("no")) {
            androidx.core.view.V.f0(t3, 2);
        } else if (str.equals("no-hide-descendants")) {
            androidx.core.view.V.f0(t3, 4);
        }
    }

    @K1.a(name = "mixBlendMode")
    public void setMixBlendMode(T t3, String str) {
        if (L1.a.c(t3) == 2) {
            t3.setTag(AbstractC0339k.f5594r, C0476w.b(str));
            if (t3.getParent() instanceof View) {
                ((View) t3.getParent()).invalidate();
            }
        }
    }

    @K1.a(name = "onMoveShouldSetResponder")
    public void setMoveShouldSetResponder(T t3, boolean z3) {
    }

    @K1.a(name = "onMoveShouldSetResponderCapture")
    public void setMoveShouldSetResponderCapture(T t3, boolean z3) {
    }

    @K1.a(name = "nativeID")
    public void setNativeId(T t3, String str) {
        t3.setTag(AbstractC0339k.f5576E, str);
        R1.a.c(t3);
    }

    @K1.a(defaultFloat = 1.0f, name = "opacity")
    public void setOpacity(T t3, float f3) {
        t3.setAlpha(f3);
    }

    @K1.a(customType = "Color", name = "outlineColor")
    public void setOutlineColor(T t3, Integer num) {
        C0433a.w(t3, num);
    }

    @K1.a(name = "outlineOffset")
    public void setOutlineOffset(T t3, float f3) {
        C0433a.x(t3, f3);
    }

    @K1.a(name = "outlineStyle")
    public void setOutlineStyle(T t3, String str) {
        C0433a.y(t3, str == null ? null : Q1.o.b(str));
    }

    @K1.a(name = "outlineWidth")
    public void setOutlineWidth(T t3, float f3) {
        C0433a.z(t3, f3);
    }

    @K1.a(name = "onPointerEnter")
    public void setPointerEnter(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2111h, z3);
    }

    @K1.a(name = "onPointerEnterCapture")
    public void setPointerEnterCapture(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2112i, z3);
    }

    @K1.a(name = "onPointerLeave")
    public void setPointerLeave(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2113j, z3);
    }

    @K1.a(name = "onPointerLeaveCapture")
    public void setPointerLeaveCapture(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2114k, z3);
    }

    @K1.a(name = "onPointerMove")
    public void setPointerMove(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2115l, z3);
    }

    @K1.a(name = "onPointerMoveCapture")
    public void setPointerMoveCapture(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2116m, z3);
    }

    @K1.a(name = "onPointerOut")
    public void setPointerOut(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2119p, z3);
    }

    @K1.a(name = "onPointerOutCapture")
    public void setPointerOutCapture(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2120q, z3);
    }

    @K1.a(name = "onPointerOver")
    public void setPointerOver(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2121r, z3);
    }

    @K1.a(name = "onPointerOverCapture")
    public void setPointerOverCapture(T t3, boolean z3) {
        setPointerEventsFlag(t3, o.a.f2122s, z3);
    }

    @K1.a(name = "renderToHardwareTextureAndroid")
    public void setRenderToHardwareTexture(T t3, boolean z3) {
        t3.setTag(AbstractC0339k.f5574C, Boolean.valueOf(z3));
    }

    @K1.a(name = "onResponderEnd")
    public void setResponderEnd(T t3, boolean z3) {
    }

    @K1.a(name = "onResponderGrant")
    public void setResponderGrant(T t3, boolean z3) {
    }

    @K1.a(name = "onResponderMove")
    public void setResponderMove(T t3, boolean z3) {
    }

    @K1.a(name = "onResponderReject")
    public void setResponderReject(T t3, boolean z3) {
    }

    @K1.a(name = "onResponderRelease")
    public void setResponderRelease(T t3, boolean z3) {
    }

    @K1.a(name = "onResponderStart")
    public void setResponderStart(T t3, boolean z3) {
    }

    @K1.a(name = "onResponderTerminate")
    public void setResponderTerminate(T t3, boolean z3) {
    }

    @K1.a(name = "onResponderTerminationRequest")
    public void setResponderTerminationRequest(T t3, boolean z3) {
    }

    @K1.a(name = "role")
    public void setRole(T t3, String str) {
        if (str == null) {
            t3.setTag(AbstractC0339k.f5602z, null);
        } else {
            t3.setTag(AbstractC0339k.f5602z, C0448h0.e.b(str));
        }
    }

    @K1.a(name = "rotation")
    @Deprecated
    public void setRotation(T t3, float f3) {
        t3.setRotation(f3);
    }

    @K1.a(defaultFloat = 1.0f, name = "scaleX")
    @Deprecated
    public void setScaleX(T t3, float f3) {
        t3.setScaleX(f3);
    }

    @K1.a(defaultFloat = 1.0f, name = "scaleY")
    @Deprecated
    public void setScaleY(T t3, float f3) {
        t3.setScaleY(f3);
    }

    @K1.a(customType = "Color", defaultInt = -16777216, name = "shadowColor")
    public void setShadowColor(T t3, int i3) {
        if (Build.VERSION.SDK_INT >= 28) {
            t3.setOutlineAmbientShadowColor(i3);
            t3.setOutlineSpotShadowColor(i3);
        }
    }

    @K1.a(name = "onShouldBlockNativeResponder")
    public void setShouldBlockNativeResponder(T t3, boolean z3) {
    }

    @K1.a(name = "onStartShouldSetResponder")
    public void setStartShouldSetResponder(T t3, boolean z3) {
    }

    @K1.a(name = "onStartShouldSetResponderCapture")
    public void setStartShouldSetResponderCapture(T t3, boolean z3) {
    }

    @K1.a(name = "testID")
    public void setTestId(T t3, String str) {
        t3.setTag(AbstractC0339k.f5596t, str);
        t3.setTag(str);
    }

    @K1.a(name = "onTouchCancel")
    public void setTouchCancel(T t3, boolean z3) {
    }

    @K1.a(name = "onTouchEnd")
    public void setTouchEnd(T t3, boolean z3) {
    }

    @K1.a(name = "onTouchMove")
    public void setTouchMove(T t3, boolean z3) {
    }

    @K1.a(name = "onTouchStart")
    public void setTouchStart(T t3, boolean z3) {
    }

    @K1.a(name = "transform")
    public void setTransform(T t3, ReadableArray readableArray) {
        if (Objects.equals((ReadableArray) t3.getTag(AbstractC0339k.f5572A), readableArray)) {
            return;
        }
        t3.setTag(AbstractC0339k.f5572A, readableArray);
        t3.setTag(AbstractC0339k.f5592p, Boolean.TRUE);
    }

    @K1.a(name = "transformOrigin")
    public void setTransformOrigin(T t3, ReadableArray readableArray) {
        if (Objects.equals((ReadableArray) t3.getTag(AbstractC0339k.f5573B), readableArray)) {
            return;
        }
        t3.setTag(AbstractC0339k.f5573B, readableArray);
        t3.setTag(AbstractC0339k.f5592p, Boolean.TRUE);
    }

    protected void setTransformProperty(T t3, ReadableArray readableArray, ReadableArray readableArray2) {
        if (readableArray == null) {
            t3.setTranslationX(C0444f0.h(0.0f));
            t3.setTranslationY(C0444f0.h(0.0f));
            t3.setRotation(0.0f);
            t3.setRotationX(0.0f);
            t3.setRotationY(0.0f);
            t3.setScaleX(1.0f);
            t3.setScaleY(1.0f);
            t3.setCameraDistance(0.0f);
            return;
        }
        boolean z3 = L1.a.c(t3) == 2;
        Y.a aVar = sMatrixDecompositionContext;
        aVar.a();
        double[] dArr = sTransformDecompositionArray;
        E0.d(readableArray, dArr, C0444f0.f(t3.getWidth()), C0444f0.f(t3.getHeight()), readableArray2, z3);
        Y.k(dArr, aVar);
        t3.setTranslationX(C0444f0.h(sanitizeFloatPropertyValue((float) aVar.f7560d[0])));
        t3.setTranslationY(C0444f0.h(sanitizeFloatPropertyValue((float) aVar.f7560d[1])));
        t3.setRotation(sanitizeFloatPropertyValue((float) aVar.f7561e[2]));
        t3.setRotationX(sanitizeFloatPropertyValue((float) aVar.f7561e[0]));
        t3.setRotationY(sanitizeFloatPropertyValue((float) aVar.f7561e[1]));
        t3.setScaleX(sanitizeFloatPropertyValue((float) aVar.f7558b[0]));
        t3.setScaleY(sanitizeFloatPropertyValue((float) aVar.f7558b[1]));
        double[] dArr2 = aVar.f7557a;
        if (dArr2.length > 2) {
            float f3 = (float) dArr2[2];
            if (f3 == 0.0f) {
                f3 = 7.8125E-4f;
            }
            float f4 = (-1.0f) / f3;
            float f5 = C0478x.c().density;
            t3.setCameraDistance(sanitizeFloatPropertyValue(f5 * f5 * f4 * CAMERA_DISTANCE_NORMALIZATION_MULTIPLIER));
        }
    }

    @K1.a(defaultFloat = 0.0f, name = "translateX")
    @Deprecated
    public void setTranslateX(T t3, float f3) {
        t3.setTranslationX(C0444f0.h(f3));
    }

    @K1.a(defaultFloat = 0.0f, name = "translateY")
    @Deprecated
    public void setTranslateY(T t3, float f3) {
        t3.setTranslationY(C0444f0.h(f3));
    }

    @K1.a(name = "accessibilityState")
    public void setViewState(T t3, ReadableMap readableMap) {
        if (readableMap == null) {
            return;
        }
        if (readableMap.hasKey(STATE_EXPANDED)) {
            t3.setTag(AbstractC0339k.f5585i, Boolean.valueOf(readableMap.getBoolean(STATE_EXPANDED)));
        }
        if (readableMap.hasKey("selected")) {
            boolean zIsSelected = t3.isSelected();
            boolean z3 = readableMap.getBoolean("selected");
            t3.setSelected(z3);
            if (t3.isAccessibilityFocused() && zIsSelected && !z3) {
                t3.announceForAccessibility(t3.getContext().getString(AbstractC0342n.f5617G));
            }
        } else {
            t3.setSelected(false);
        }
        t3.setTag(AbstractC0339k.f5584h, readableMap);
        if (readableMap.hasKey("disabled") && !readableMap.getBoolean("disabled")) {
            t3.setEnabled(true);
        }
        ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = readableMap.keySetIterator();
        while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
            String strNextKey = readableMapKeySetIteratorKeySetIterator.nextKey();
            if (strNextKey.equals(STATE_BUSY) || strNextKey.equals(STATE_EXPANDED) || (strNextKey.equals(STATE_CHECKED) && readableMap.getType(STATE_CHECKED) == ReadableType.String)) {
                updateViewContentDescription(t3);
                return;
            } else if (t3.isAccessibilityFocused()) {
                t3.sendAccessibilityEvent(1);
            }
        }
    }

    @K1.a(name = "zIndex")
    public void setZIndex(T t3, float f3) {
        ViewGroupManager.setViewZIndex(t3, Math.round(f3));
        ViewParent parent = t3.getParent();
        if (parent instanceof InterfaceC0475v0) {
            ((InterfaceC0475v0) parent).f();
        }
    }

    protected void updateViewAccessibility(T t3) {
        C0448h0.g0(t3, t3.isFocusable(), t3.getImportantForAccessibility());
    }

    public BaseViewManager(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }
}
