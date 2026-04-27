package com.facebook.react.views.text;

import android.content.Context;
import android.os.Build;
import android.text.Spannable;
import c1.AbstractC0339k;
import com.facebook.react.common.mapbuffer.ReadableMapBuffer;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0469s0;
import com.facebook.react.uimanager.O;
import com.facebook.react.views.text.m;
import d1.AbstractC0508d;
import java.util.HashMap;
import java.util.Map;
import p1.C0649c;
import q1.C0655b;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactTextViewManager.REACT_CLASS)
public class ReactTextViewManager extends ReactTextAnchorViewManager<l, g> implements O {
    public static final String REACT_CLASS = "RCTText";
    private static final String TAG = "ReactTextViewManager";
    private static final short TX_STATE_KEY_ATTRIBUTED_STRING = 0;
    private static final short TX_STATE_KEY_HASH = 2;
    private static final short TX_STATE_KEY_MOST_RECENT_EVENT_COUNT = 3;
    private static final short TX_STATE_KEY_PARAGRAPH_ATTRIBUTES = 1;
    protected n mReactTextViewManagerCallback;

    public ReactTextViewManager() {
        this(null);
    }

    private Object getReactTextUpdate(l lVar, C0469s0 c0469s0, com.facebook.react.common.mapbuffer.a aVar) {
        com.facebook.react.common.mapbuffer.a aVarD = aVar.d(0);
        com.facebook.react.common.mapbuffer.a aVarD2 = aVar.d(1);
        Spannable spannableG = s.g(lVar.getContext(), aVarD, null);
        lVar.setSpanned(spannableG);
        try {
            lVar.setMinimumFontSize((float) aVarD2.getDouble(6));
            return new h(spannableG, -1, false, s.j(aVarD, spannableG, lVar.getGravityHorizontal()), q.m(aVarD2.getString(2)), q.h(c0469s0, Build.VERSION.SDK_INT >= 26 ? lVar.getJustificationMode() : 0));
        } catch (IllegalArgumentException e3) {
            Y.a.o(TAG, "Paragraph Attributes: %s", aVarD2 != null ? aVarD2.toString() : "<empty>");
            throw e3;
        }
    }

    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public Map getExportedCustomDirectEventTypeConstants() {
        Map<String, Object> exportedCustomDirectEventTypeConstants = super.getExportedCustomDirectEventTypeConstants();
        if (exportedCustomDirectEventTypeConstants == null) {
            exportedCustomDirectEventTypeConstants = new HashMap<>();
        }
        exportedCustomDirectEventTypeConstants.putAll(AbstractC0508d.e("topTextLayout", AbstractC0508d.d("registrationName", "onTextLayout"), "topInlineViewLayout", AbstractC0508d.d("registrationName", "onInlineViewLayout")));
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Class<g> getShadowNodeClass() {
        return g.class;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public long measure(Context context, com.facebook.react.common.mapbuffer.a aVar, com.facebook.react.common.mapbuffer.a aVar2, com.facebook.react.common.mapbuffer.a aVar3, float f3, com.facebook.yoga.p pVar, float f4, com.facebook.yoga.p pVar2, float[] fArr) {
        return s.n(context, aVar, aVar2, f3, pVar, f4, pVar2, null, fArr);
    }

    @Override // com.facebook.react.uimanager.O
    public boolean needsCustomLayoutForChildren() {
        return true;
    }

    @K1.a(name = "overflow")
    public void setOverflow(l lVar, String str) {
        lVar.setOverflow(str);
    }

    public ReactTextViewManager(n nVar) {
        if (C0655b.k()) {
            setupViewRecycling();
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public g createShadowNodeInstance() {
        return new g(null);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public l createViewInstance(B0 b02) {
        return new l(b02);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public void onAfterUpdateTransaction(l lVar) {
        super.onAfterUpdateTransaction(lVar);
        lVar.y();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public l prepareToRecycleView(B0 b02, l lVar) {
        l lVar2 = (l) super.prepareToRecycleView(b02, lVar);
        if (lVar2 != null) {
            lVar2.w();
            setSelectionColor(lVar2, null);
        }
        return lVar;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void setPadding(l lVar, int i3, int i4, int i5, int i6) {
        lVar.setPadding(i3, i4, i5, i6);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void updateExtraData(l lVar, Object obj) {
        C0649c c0649c = new C0649c("ReactTextViewManager.updateExtraData");
        try {
            h hVar = (h) obj;
            Spannable spannableI = hVar.i();
            if (hVar.b()) {
                Y1.p.g(spannableI, lVar);
            }
            lVar.setText(hVar);
            Y1.f[] fVarArr = (Y1.f[]) spannableI.getSpans(0, hVar.i().length(), Y1.f.class);
            lVar.setTag(AbstractC0339k.f5582f, fVarArr.length > 0 ? new m.a(fVarArr, spannableI) : null);
            m.f8126y.a(lVar, lVar.isFocusable(), lVar.getImportantForAccessibility());
            c0649c.close();
        } catch (Throwable th) {
            try {
                c0649c.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Object updateState(l lVar, C0469s0 c0469s0, A0 a02) {
        C0649c c0649c = new C0649c("ReactTextViewManager.updateState");
        try {
            ReadableMapBuffer readableMapBufferE = a02.e();
            if (readableMapBufferE == null) {
                c0649c.close();
                return null;
            }
            Object reactTextUpdate = getReactTextUpdate(lVar, c0469s0, readableMapBufferE);
            c0649c.close();
            return reactTextUpdate;
        } catch (Throwable th) {
            try {
                c0649c.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager
    public void updateViewAccessibility(l lVar) {
        m.f8126y.b(lVar, lVar.isFocusable(), lVar.getImportantForAccessibility());
    }

    public g createShadowNodeInstance(n nVar) {
        return new g(nVar);
    }
}
