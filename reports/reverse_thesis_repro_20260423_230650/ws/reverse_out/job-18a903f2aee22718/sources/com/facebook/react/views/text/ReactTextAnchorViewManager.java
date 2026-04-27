package com.facebook.react.views.text;

import android.text.TextUtils;
import android.view.View;
import com.facebook.react.animated.NativeAnimatedModule;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.views.text.c;

/* JADX INFO: loaded from: classes.dex */
public abstract class ReactTextAnchorViewManager<T extends View, C extends c> extends BaseViewManager<T, C> {
    private static final int[] SPACING_TYPES = {8, 0, 2, 1, 3, 4, 5};
    private static final String TAG = "ReactTextAnchorViewManager";

    @K1.a(name = "accessible")
    public void setAccessible(l lVar, boolean z3) {
        lVar.setFocusable(z3);
    }

    @K1.a(name = "adjustsFontSizeToFit")
    public void setAdjustFontSizeToFit(l lVar, boolean z3) {
        lVar.setAdjustFontSizeToFit(z3);
    }

    @K1.a(name = "android_hyphenationFrequency")
    public void setAndroidHyphenationFrequency(l lVar, String str) {
        if (str == null || str.equals("none")) {
            lVar.setHyphenationFrequency(0);
            return;
        }
        if (str.equals("full")) {
            lVar.setHyphenationFrequency(2);
            return;
        }
        if (str.equals("normal")) {
            lVar.setHyphenationFrequency(1);
            return;
        }
        Y.a.I("ReactNative", "Invalid android_hyphenationFrequency: " + str);
        lVar.setHyphenationFrequency(0);
    }

    @K1.b(customType = "Color", names = {"borderColor", "borderLeftColor", "borderRightColor", "borderTopColor", "borderBottomColor"})
    public void setBorderColor(l lVar, int i3, Integer num) {
        C0433a.p(lVar, Q1.n.f2478c, num);
    }

    @K1.b(defaultFloat = Float.NaN, names = {"borderRadius", "borderTopLeftRadius", "borderTopRightRadius", "borderBottomRightRadius", "borderBottomLeftRadius"})
    public void setBorderRadius(l lVar, int i3, float f3) {
        C0433a.q(lVar, Q1.d.values()[i3], Float.isNaN(f3) ? null : new W(f3, X.f7535b));
    }

    @K1.a(name = "borderStyle")
    public void setBorderStyle(l lVar, String str) {
        C0433a.r(lVar, str == null ? null : Q1.f.b(str));
    }

    @K1.b(defaultFloat = Float.NaN, names = {"borderWidth", "borderLeftWidth", "borderRightWidth", "borderTopWidth", "borderBottomWidth", "borderStartWidth", "borderEndWidth"})
    public void setBorderWidth(l lVar, int i3, float f3) {
        C0433a.s(lVar, Q1.n.values()[i3], Float.valueOf(f3));
    }

    @K1.a(name = "dataDetectorType")
    public void setDataDetectorType(l lVar, String str) {
        if (str != null) {
            switch (str) {
                case "phoneNumber":
                    lVar.setLinkifyMask(4);
                    break;
                case "all":
                    lVar.setLinkifyMask(15);
                    break;
                case "link":
                    lVar.setLinkifyMask(1);
                    break;
                case "email":
                    lVar.setLinkifyMask(2);
                    break;
            }
            return;
        }
        lVar.setLinkifyMask(0);
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "disabled")
    public void setDisabled(l lVar, boolean z3) {
        lVar.setEnabled(!z3);
    }

    @K1.a(name = "ellipsizeMode")
    public void setEllipsizeMode(l lVar, String str) {
        if (str == null || str.equals("tail")) {
            lVar.setEllipsizeLocation(TextUtils.TruncateAt.END);
            return;
        }
        if (str.equals("head")) {
            lVar.setEllipsizeLocation(TextUtils.TruncateAt.START);
            return;
        }
        if (str.equals("middle")) {
            lVar.setEllipsizeLocation(TextUtils.TruncateAt.MIDDLE);
            return;
        }
        if (str.equals("clip")) {
            lVar.setEllipsizeLocation(null);
            return;
        }
        Y.a.I("ReactNative", "Invalid ellipsizeMode: " + str);
        lVar.setEllipsizeLocation(TextUtils.TruncateAt.END);
    }

    @K1.a(name = "fontSize")
    public void setFontSize(l lVar, float f3) {
        lVar.setFontSize(f3);
    }

    @K1.a(defaultBoolean = true, name = "includeFontPadding")
    public void setIncludeFontPadding(l lVar, boolean z3) {
        lVar.setIncludeFontPadding(z3);
    }

    @K1.a(defaultFloat = 0.0f, name = "letterSpacing")
    public void setLetterSpacing(l lVar, float f3) {
        lVar.setLetterSpacing(f3);
    }

    @K1.a(name = "onInlineViewLayout")
    public void setNotifyOnInlineViewLayout(l lVar, boolean z3) {
        lVar.setNotifyOnInlineViewLayout(z3);
    }

    @K1.a(defaultInt = Integer.MAX_VALUE, name = "numberOfLines")
    public void setNumberOfLines(l lVar, int i3) {
        lVar.setNumberOfLines(i3);
    }

    @K1.a(name = "selectable")
    public void setSelectable(l lVar, boolean z3) {
        lVar.setTextIsSelectable(z3);
    }

    @K1.a(customType = "Color", name = "selectionColor")
    public void setSelectionColor(l lVar, Integer num) {
        if (num == null) {
            lVar.setHighlightColor(a.c(lVar.getContext()));
        } else {
            lVar.setHighlightColor(num.intValue());
        }
    }

    @K1.a(name = "textAlignVertical")
    public void setTextAlignVertical(l lVar, String str) {
        if (str == null || "auto".equals(str)) {
            lVar.setGravityVertical(0);
            return;
        }
        if ("top".equals(str)) {
            lVar.setGravityVertical(48);
            return;
        }
        if ("bottom".equals(str)) {
            lVar.setGravityVertical(80);
            return;
        }
        if ("center".equals(str)) {
            lVar.setGravityVertical(16);
            return;
        }
        Y.a.I("ReactNative", "Invalid textAlignVertical: " + str);
        lVar.setGravityVertical(0);
    }
}
