package com.facebook.react.views.textinput;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.BlendMode;
import android.graphics.BlendModeColorFilter;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.InputFilter;
import android.text.SpannableStringBuilder;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import com.facebook.react.animated.NativeAnimatedModule;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.common.mapbuffer.ReadableMapBuffer;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.AbstractC0480y;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.C0469s0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.U;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.uimanager.events.EventDispatcher;
import d1.AbstractC0508d;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactTextInputManager.REACT_CLASS)
public class ReactTextInputManager extends BaseViewManager<C0493j, U> {
    private static final int AUTOCAPITALIZE_FLAGS = 28672;
    private static final int BLUR_TEXT_INPUT = 2;
    private static final int FOCUS_TEXT_INPUT = 1;
    private static final int IME_ACTION_ID = 1648;
    private static final int INPUT_TYPE_KEYBOARD_DECIMAL_PAD = 8194;
    private static final int INPUT_TYPE_KEYBOARD_NUMBERED = 12290;
    private static final int INPUT_TYPE_KEYBOARD_NUMBER_PAD = 2;
    private static final String KEYBOARD_TYPE_DECIMAL_PAD = "decimal-pad";
    private static final String KEYBOARD_TYPE_EMAIL_ADDRESS = "email-address";
    private static final String KEYBOARD_TYPE_NUMBER_PAD = "number-pad";
    private static final String KEYBOARD_TYPE_NUMERIC = "numeric";
    private static final String KEYBOARD_TYPE_PHONE_PAD = "phone-pad";
    private static final String KEYBOARD_TYPE_URI = "url";
    private static final String KEYBOARD_TYPE_VISIBLE_PASSWORD = "visible-password";
    private static final int PASSWORD_VISIBILITY_FLAG = 16;
    public static final String REACT_CLASS = "AndroidTextInput";
    private static final int SET_TEXT_AND_SELECTION = 4;
    public static final String TAG = "ReactTextInputManager";
    private static final short TX_STATE_KEY_ATTRIBUTED_STRING = 0;
    private static final short TX_STATE_KEY_HASH = 2;
    private static final short TX_STATE_KEY_MOST_RECENT_EVENT_COUNT = 3;
    private static final short TX_STATE_KEY_PARAGRAPH_ATTRIBUTES = 1;
    private static final int UNSET = -1;
    protected com.facebook.react.views.text.n mReactTextViewManagerCallback;
    private static final int SET_MOST_RECENT_EVENT_COUNT = 3;
    private static final int[] SPACING_TYPES = {8, 0, 2, 1, SET_MOST_RECENT_EVENT_COUNT};
    private static final Map<String, String> REACT_PROPS_AUTOFILL_HINTS_MAP = new a();
    private static final InputFilter[] EMPTY_FILTERS = new InputFilter[0];
    private static final String[] DRAWABLE_HANDLE_RESOURCES = {"mTextSelectHandleLeftRes", "mTextSelectHandleRightRes", "mTextSelectHandleRes"};
    private static final String[] DRAWABLE_HANDLE_FIELDS = {"mSelectHandleLeft", "mSelectHandleRight", "mSelectHandleCenter"};

    class a extends HashMap {
        a() {
            put("birthdate-day", "birthDateDay");
            put("birthdate-full", "birthDateFull");
            put("birthdate-month", "birthDateMonth");
            put("birthdate-year", "birthDateYear");
            put("cc-csc", "creditCardSecurityCode");
            put("cc-exp", "creditCardExpirationDate");
            put("cc-exp-day", "creditCardExpirationDay");
            put("cc-exp-month", "creditCardExpirationMonth");
            put("cc-exp-year", "creditCardExpirationYear");
            put("cc-number", "creditCardNumber");
            put("email", "emailAddress");
            put("gender", "gender");
            put("name", "personName");
            put("name-family", "personFamilyName");
            put("name-given", "personGivenName");
            put("name-middle", "personMiddleName");
            put("name-middle-initial", "personMiddleInitial");
            put("name-prefix", "personNamePrefix");
            put("name-suffix", "personNameSuffix");
            put("password", "password");
            put("password-new", "newPassword");
            put("postal-address", "postalAddress");
            put("postal-address-country", "addressCountry");
            put("postal-address-extended", "extendedAddress");
            put("postal-address-extended-postal-code", "extendedPostalCode");
            put("postal-address-locality", "addressLocality");
            put("postal-address-region", "addressRegion");
            put("postal-code", "postalCode");
            put("street-address", "streetAddress");
            put("sms-otp", "smsOTPCode");
            put("tel", "phoneNumber");
            put("tel-country-code", "phoneCountryCode");
            put("tel-national", "phoneNational");
            put("tel-device", "phoneNumberDevice");
            put("username", "username");
            put("username-new", "newUsername");
        }
    }

    private static class b implements InterfaceC0484a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final C0493j f8198a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final EventDispatcher f8199b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f8200c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f8201d = 0;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f8202e = 0;

        public b(C0493j c0493j) {
            this.f8198a = c0493j;
            ReactContext reactContextD = H0.d(c0493j);
            this.f8199b = ReactTextInputManager.getEventDispatcher(reactContextD, c0493j);
            this.f8200c = H0.e(reactContextD);
        }

        @Override // com.facebook.react.views.textinput.InterfaceC0484a
        public void a() {
            if (this.f8199b == null) {
                return;
            }
            int width = this.f8198a.getWidth();
            int height = this.f8198a.getHeight();
            if (this.f8198a.getLayout() != null) {
                width = this.f8198a.getCompoundPaddingLeft() + this.f8198a.getLayout().getWidth() + this.f8198a.getCompoundPaddingRight();
                height = this.f8198a.getCompoundPaddingTop() + this.f8198a.getLayout().getHeight() + this.f8198a.getCompoundPaddingBottom();
            }
            if (width == this.f8201d && height == this.f8202e) {
                return;
            }
            this.f8202e = height;
            this.f8201d = width;
            this.f8199b.g(new C0485b(this.f8200c, this.f8198a.getId(), C0444f0.f(width), C0444f0.f(height)));
        }
    }

    private static class c implements J {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final C0493j f8203a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final EventDispatcher f8204b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f8205c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f8206d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f8207e;

        public c(C0493j c0493j) {
            this.f8203a = c0493j;
            ReactContext reactContextD = H0.d(c0493j);
            this.f8204b = ReactTextInputManager.getEventDispatcher(reactContextD, c0493j);
            this.f8205c = H0.e(reactContextD);
        }

        @Override // com.facebook.react.views.textinput.J
        public void a(int i3, int i4, int i5, int i6) {
            if (this.f8206d == i3 && this.f8207e == i4) {
                return;
            }
            this.f8204b.g(com.facebook.react.views.scroll.k.x(this.f8205c, this.f8203a.getId(), com.facebook.react.views.scroll.l.f8017e, i3, i4, 0.0f, 0.0f, 0, 0, this.f8203a.getWidth(), this.f8203a.getHeight()));
            this.f8206d = i3;
            this.f8207e = i4;
        }
    }

    private static class d implements K {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final C0493j f8208a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final EventDispatcher f8209b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f8210c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f8211d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f8212e;

        public d(C0493j c0493j) {
            this.f8208a = c0493j;
            ReactContext reactContextD = H0.d(c0493j);
            this.f8209b = ReactTextInputManager.getEventDispatcher(reactContextD, c0493j);
            this.f8210c = H0.e(reactContextD);
        }

        @Override // com.facebook.react.views.textinput.K
        public void a(int i3, int i4) {
            int iMin = Math.min(i3, i4);
            int iMax = Math.max(i3, i4);
            if (this.f8211d == iMin && this.f8212e == iMax) {
                return;
            }
            this.f8209b.g(new G(this.f8210c, this.f8208a.getId(), iMin, iMax));
            this.f8211d = iMin;
            this.f8212e = iMax;
        }
    }

    private final class e implements TextWatcher {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final C0493j f8213b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final EventDispatcher f8214c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int f8215d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private String f8216e = null;

        public e(ReactContext reactContext, C0493j c0493j) {
            this.f8214c = ReactTextInputManager.getEventDispatcher(reactContext, c0493j);
            this.f8213b = c0493j;
            this.f8215d = H0.e(reactContext);
        }

        @Override // android.text.TextWatcher
        public void afterTextChanged(Editable editable) {
        }

        @Override // android.text.TextWatcher
        public void beforeTextChanged(CharSequence charSequence, int i3, int i4, int i5) {
            this.f8216e = charSequence.toString();
        }

        @Override // android.text.TextWatcher
        public void onTextChanged(CharSequence charSequence, int i3, int i4, int i5) {
            if (this.f8213b.f8241M) {
                return;
            }
            if (i5 == 0 && i4 == 0) {
                return;
            }
            Z0.a.c(this.f8216e);
            String strSubstring = charSequence.toString().substring(i3, i3 + i5);
            String strSubstring2 = this.f8216e.substring(i3, i3 + i4);
            if (i5 == i4 && strSubstring.equals(strSubstring2)) {
                return;
            }
            A0 stateWrapper = this.f8213b.getStateWrapper();
            if (stateWrapper != null) {
                WritableNativeMap writableNativeMap = new WritableNativeMap();
                writableNativeMap.putInt("mostRecentEventCount", this.f8213b.A());
                writableNativeMap.putInt("opaqueCacheId", this.f8213b.getId());
                stateWrapper.b(writableNativeMap);
            }
            this.f8214c.g(new m(this.f8215d, this.f8213b.getId(), charSequence.toString(), this.f8213b.A()));
        }
    }

    private static void checkPasswordType(C0493j c0493j) {
        if ((c0493j.getStagedInputType() & INPUT_TYPE_KEYBOARD_NUMBERED) == 0 || (c0493j.getStagedInputType() & 128) == 0) {
            return;
        }
        updateStagedInputTypeFlag(c0493j, 128, PASSWORD_VISIBILITY_FLAG);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static EventDispatcher getEventDispatcher(ReactContext reactContext, C0493j c0493j) {
        return H0.c(reactContext, c0493j.getId());
    }

    private com.facebook.react.views.text.h getReactTextUpdate(String str, int i3) {
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder();
        spannableStringBuilder.append((CharSequence) com.facebook.react.views.text.t.b(str, com.facebook.react.views.text.t.f8182g));
        return new com.facebook.react.views.text.h(spannableStringBuilder, i3, false, 0.0f, 0.0f, 0.0f, 0.0f, 0, 0, 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void lambda$addEventEmitters$0(B0 b02, C0493j c0493j, View view, boolean z3) {
        int iC = b02.c();
        EventDispatcher eventDispatcher = getEventDispatcher(b02, c0493j);
        if (z3) {
            eventDispatcher.g(new p(iC, c0493j.getId()));
        } else {
            eventDispatcher.g(new n(iC, c0493j.getId()));
            eventDispatcher.g(new o(iC, c0493j.getId(), c0493j.getText().toString()));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ boolean lambda$addEventEmitters$1(C0493j c0493j, B0 b02, TextView textView, int i3, KeyEvent keyEvent) {
        if ((i3 & 255) == 0 && i3 != 0) {
            return true;
        }
        boolean zB = c0493j.B();
        boolean Z2 = c0493j.Z();
        boolean zY = c0493j.Y();
        if (Z2) {
            getEventDispatcher(b02, c0493j).g(new I(b02.c(), c0493j.getId(), c0493j.getText().toString()));
        }
        if (zY) {
            c0493j.clearFocus();
        }
        return zY || Z2 || !zB || i3 == 5 || i3 == 7;
    }

    private void setAutofillHints(C0493j c0493j, String... strArr) {
        if (Build.VERSION.SDK_INT < 26) {
            return;
        }
        c0493j.setAutofillHints(strArr);
    }

    private static boolean shouldHideCursorForEmailTextInput() {
        return Build.VERSION.SDK_INT == 29 && Build.MANUFACTURER.toLowerCase(Locale.ROOT).contains("xiaomi");
    }

    private static void updateStagedInputTypeFlag(C0493j c0493j, int i3, int i4) {
        c0493j.setStagedInputType(((~i3) & c0493j.getStagedInputType()) | i4);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Integer> getCommandsMap() {
        return AbstractC0508d.e("focusTextInput", 1, "blurTextInput", 2);
    }

    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedCustomBubblingEventTypeConstants() {
        Map<String, Object> exportedCustomBubblingEventTypeConstants = super.getExportedCustomBubblingEventTypeConstants();
        if (exportedCustomBubblingEventTypeConstants == null) {
            exportedCustomBubblingEventTypeConstants = new HashMap<>();
        }
        exportedCustomBubblingEventTypeConstants.putAll(AbstractC0508d.a().b("topSubmitEditing", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onSubmitEditing", "captured", "onSubmitEditingCapture"))).b("topEndEditing", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onEndEditing", "captured", "onEndEditingCapture"))).b("topFocus", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onFocus", "captured", "onFocusCapture"))).b("topBlur", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onBlur", "captured", "onBlurCapture"))).b("topKeyPress", AbstractC0508d.d("phasedRegistrationNames", AbstractC0508d.e("bubbled", "onKeyPress", "captured", "onKeyPressCapture"))).a());
        return exportedCustomBubblingEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedCustomDirectEventTypeConstants() {
        Map<String, Object> exportedCustomDirectEventTypeConstants = super.getExportedCustomDirectEventTypeConstants();
        if (exportedCustomDirectEventTypeConstants == null) {
            exportedCustomDirectEventTypeConstants = new HashMap<>();
        }
        exportedCustomDirectEventTypeConstants.putAll(AbstractC0508d.a().b(com.facebook.react.views.scroll.l.b(com.facebook.react.views.scroll.l.f8017e), AbstractC0508d.d("registrationName", "onScroll")).a());
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedViewConstants() {
        return AbstractC0508d.d("AutoCapitalizationType", AbstractC0508d.g("none", 0, "characters", 4096, "words", 8192, "sentences", 16384));
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Class<? extends U> getShadowNodeClass() {
        return H.class;
    }

    @K1.a(defaultBoolean = true, name = "allowFontScaling")
    public void setAllowFontScaling(C0493j c0493j, boolean z3) {
        c0493j.setAllowFontScaling(z3);
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:29:0x005a  */
    @K1.a(name = "autoCapitalize")
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setAutoCapitalize(com.facebook.react.views.textinput.C0493j r5, com.facebook.react.bridge.Dynamic r6) {
        /*
            r4 = this;
            r0 = 0
            com.facebook.react.bridge.ReadableType r1 = r6.getType()
            com.facebook.react.bridge.ReadableType r2 = com.facebook.react.bridge.ReadableType.Number
            if (r1 != r2) goto Le
            int r0 = r6.asInt()
            goto L5e
        Le:
            com.facebook.react.bridge.ReadableType r1 = r6.getType()
            com.facebook.react.bridge.ReadableType r2 = com.facebook.react.bridge.ReadableType.String
            r3 = 16384(0x4000, float:2.2959E-41)
            if (r1 != r2) goto L5a
            java.lang.String r6 = r6.asString()
            r6.hashCode()
            r1 = -1
            int r2 = r6.hashCode()
            switch(r2) {
                case 3387192: goto L49;
                case 113318569: goto L3e;
                case 490141296: goto L33;
                case 1245424234: goto L28;
                default: goto L27;
            }
        L27:
            goto L53
        L28:
            java.lang.String r2 = "characters"
            boolean r6 = r6.equals(r2)
            if (r6 != 0) goto L31
            goto L53
        L31:
            r1 = 3
            goto L53
        L33:
            java.lang.String r2 = "sentences"
            boolean r6 = r6.equals(r2)
            if (r6 != 0) goto L3c
            goto L53
        L3c:
            r1 = 2
            goto L53
        L3e:
            java.lang.String r2 = "words"
            boolean r6 = r6.equals(r2)
            if (r6 != 0) goto L47
            goto L53
        L47:
            r1 = 1
            goto L53
        L49:
            java.lang.String r2 = "none"
            boolean r6 = r6.equals(r2)
            if (r6 != 0) goto L52
            goto L53
        L52:
            r1 = r0
        L53:
            switch(r1) {
                case 0: goto L5e;
                case 1: goto L5c;
                case 2: goto L5a;
                case 3: goto L57;
                default: goto L56;
            }
        L56:
            goto L5a
        L57:
            r0 = 4096(0x1000, float:5.74E-42)
            goto L5e
        L5a:
            r0 = r3
            goto L5e
        L5c:
            r0 = 8192(0x2000, float:1.148E-41)
        L5e:
            r6 = 28672(0x7000, float:4.0178E-41)
            updateStagedInputTypeFlag(r5, r6, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.views.textinput.ReactTextInputManager.setAutoCapitalize(com.facebook.react.views.textinput.j, com.facebook.react.bridge.Dynamic):void");
    }

    @K1.a(name = "autoCorrect")
    public void setAutoCorrect(C0493j c0493j, Boolean bool) {
        updateStagedInputTypeFlag(c0493j, 557056, bool != null ? bool.booleanValue() ? 32768 : 524288 : 0);
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "autoFocus")
    public void setAutoFocus(C0493j c0493j, boolean z3) {
        c0493j.setAutoFocus(z3);
    }

    @K1.b(customType = "Color", names = {"borderColor", "borderLeftColor", "borderRightColor", "borderTopColor", "borderBottomColor"})
    public void setBorderColor(C0493j c0493j, int i3, Integer num) {
        C0433a.p(c0493j, Q1.n.f2478c, num);
    }

    @K1.b(defaultFloat = Float.NaN, names = {"borderRadius", "borderTopLeftRadius", "borderTopRightRadius", "borderBottomRightRadius", "borderBottomLeftRadius"})
    public void setBorderRadius(C0493j c0493j, int i3, float f3) {
        C0433a.q(c0493j, Q1.d.values()[i3], Float.isNaN(f3) ? null : new W(f3, X.f7535b));
    }

    @K1.a(name = "borderStyle")
    public void setBorderStyle(C0493j c0493j, String str) {
        C0433a.r(c0493j, str == null ? null : Q1.f.b(str));
    }

    @K1.b(defaultFloat = Float.NaN, names = {"borderWidth", "borderLeftWidth", "borderRightWidth", "borderTopWidth", "borderBottomWidth"})
    public void setBorderWidth(C0493j c0493j, int i3, float f3) {
        C0433a.s(c0493j, Q1.n.values()[i3], Float.valueOf(f3));
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "caretHidden")
    public void setCaretHidden(C0493j c0493j, boolean z3) {
        if (c0493j.getStagedInputType() == 32 && shouldHideCursorForEmailTextInput()) {
            return;
        }
        c0493j.setCursorVisible(!z3);
    }

    @K1.a(customType = "Color", name = "color")
    public void setColor(C0493j c0493j, Integer num) {
        if (num != null) {
            c0493j.setTextColor(num.intValue());
            return;
        }
        ColorStateList colorStateListB = com.facebook.react.views.text.a.b(c0493j.getContext());
        if (colorStateListB != null) {
            c0493j.setTextColor(colorStateListB);
            return;
        }
        Context context = c0493j.getContext();
        String str = TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("Could not get default text color from View Context: ");
        sb.append(context != null ? context.getClass().getCanonicalName() : "null");
        ReactSoftExceptionLogger.logSoftException(str, new IllegalStateException(sb.toString()));
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "contextMenuHidden")
    public void setContextMenuHidden(C0493j c0493j, boolean z3) {
        c0493j.setContextMenuHidden(z3);
    }

    @K1.a(customType = "Color", name = "cursorColor")
    public void setCursorColor(C0493j c0493j, Integer num) {
        int i3 = Build.VERSION.SDK_INT;
        if (i3 >= 29) {
            Drawable textCursorDrawable = c0493j.getTextCursorDrawable();
            if (textCursorDrawable != null) {
                if (num != null) {
                    com.facebook.react.uimanager.B.a();
                    textCursorDrawable.setColorFilter(AbstractC0480y.a(num.intValue(), BlendMode.SRC_IN));
                } else {
                    textCursorDrawable.clearColorFilter();
                }
                c0493j.setTextCursorDrawable(textCursorDrawable);
                return;
            }
            return;
        }
        if (i3 == 28) {
            return;
        }
        try {
            Field declaredField = c0493j.getClass().getDeclaredField("mCursorDrawableRes");
            declaredField.setAccessible(true);
            int i4 = declaredField.getInt(c0493j);
            if (i4 == 0) {
                return;
            }
            Drawable drawableMutate = androidx.core.content.a.d(c0493j.getContext(), i4).mutate();
            if (num != null) {
                drawableMutate.setColorFilter(num.intValue(), PorterDuff.Mode.SRC_IN);
            } else {
                drawableMutate.clearColorFilter();
            }
            Field declaredField2 = TextView.class.getDeclaredField("mEditor");
            declaredField2.setAccessible(true);
            Object obj = declaredField2.get(c0493j);
            Field declaredField3 = obj.getClass().getDeclaredField("mCursorDrawable");
            declaredField3.setAccessible(true);
            declaredField3.set(obj, new Drawable[]{drawableMutate, drawableMutate});
        } catch (IllegalAccessException | NoSuchFieldException unused) {
        }
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "disableFullscreenUI")
    public void setDisableFullscreenUI(C0493j c0493j, boolean z3) {
        c0493j.setDisableFullscreenUI(z3);
    }

    @K1.a(defaultBoolean = true, name = "editable")
    public void setEditable(C0493j c0493j, boolean z3) {
        c0493j.setEnabled(z3);
    }

    @K1.a(name = "fontFamily")
    public void setFontFamily(C0493j c0493j, String str) {
        c0493j.setFontFamily(str);
    }

    @K1.a(defaultFloat = 14.0f, name = "fontSize")
    public void setFontSize(C0493j c0493j, float f3) {
        c0493j.setFontSize(f3);
    }

    @K1.a(name = "fontStyle")
    public void setFontStyle(C0493j c0493j, String str) {
        c0493j.setFontStyle(str);
    }

    @K1.a(name = "fontVariant")
    public void setFontVariant(C0493j c0493j, ReadableArray readableArray) {
        c0493j.setFontFeatureSettings(com.facebook.react.views.text.o.c(readableArray));
    }

    @K1.a(name = "fontWeight")
    public void setFontWeight(C0493j c0493j, String str) {
        c0493j.setFontWeight(str);
    }

    @K1.a(name = "importantForAutofill")
    public void setImportantForAutofill(C0493j c0493j, String str) {
        setImportantForAutofill(c0493j, "no".equals(str) ? 2 : "noExcludeDescendants".equals(str) ? 8 : "yes".equals(str) ? 1 : "yesExcludeDescendants".equals(str) ? SET_TEXT_AND_SELECTION : 0);
    }

    @K1.a(defaultBoolean = true, name = "includeFontPadding")
    public void setIncludeFontPadding(C0493j c0493j, boolean z3) {
        c0493j.setIncludeFontPadding(z3);
    }

    @K1.a(name = "inlineImageLeft")
    public void setInlineImageLeft(C0493j c0493j, String str) {
        c0493j.setCompoundDrawablesWithIntrinsicBounds(W1.c.d().f(c0493j.getContext(), str), 0, 0, 0);
    }

    @K1.a(name = "inlineImagePadding")
    public void setInlineImagePadding(C0493j c0493j, int i3) {
        c0493j.setCompoundDrawablePadding(i3);
    }

    @K1.a(name = "keyboardType")
    public void setKeyboardType(C0493j c0493j, String str) {
        int i3;
        if (KEYBOARD_TYPE_NUMERIC.equalsIgnoreCase(str)) {
            i3 = INPUT_TYPE_KEYBOARD_NUMBERED;
        } else if (KEYBOARD_TYPE_NUMBER_PAD.equalsIgnoreCase(str)) {
            i3 = 2;
        } else if (KEYBOARD_TYPE_DECIMAL_PAD.equalsIgnoreCase(str)) {
            i3 = INPUT_TYPE_KEYBOARD_DECIMAL_PAD;
        } else if (KEYBOARD_TYPE_EMAIL_ADDRESS.equalsIgnoreCase(str)) {
            if (shouldHideCursorForEmailTextInput()) {
                c0493j.setCursorVisible(false);
            }
            i3 = 33;
        } else {
            i3 = KEYBOARD_TYPE_PHONE_PAD.equalsIgnoreCase(str) ? SET_MOST_RECENT_EVENT_COUNT : KEYBOARD_TYPE_VISIBLE_PASSWORD.equalsIgnoreCase(str) ? 144 : KEYBOARD_TYPE_URI.equalsIgnoreCase(str) ? PASSWORD_VISIBILITY_FLAG : 1;
        }
        updateStagedInputTypeFlag(c0493j, 15, i3);
        checkPasswordType(c0493j);
    }

    @K1.a(defaultFloat = 0.0f, name = "letterSpacing")
    public void setLetterSpacing(C0493j c0493j, float f3) {
        c0493j.setLetterSpacingPt(f3);
    }

    @K1.a(defaultFloat = 0.0f, name = "lineHeight")
    public void setLineHeight(C0493j c0493j, int i3) {
        c0493j.setLineHeight(i3);
    }

    @K1.a(defaultFloat = Float.NaN, name = "maxFontSizeMultiplier")
    public void setMaxFontSizeMultiplier(C0493j c0493j, float f3) {
        c0493j.setMaxFontSizeMultiplier(f3);
    }

    @K1.a(name = "maxLength")
    public void setMaxLength(C0493j c0493j, Integer num) {
        InputFilter[] filters = c0493j.getFilters();
        InputFilter[] inputFilterArr = EMPTY_FILTERS;
        if (num == null) {
            if (filters.length > 0) {
                LinkedList linkedList = new LinkedList();
                for (InputFilter inputFilter : filters) {
                    if (!(inputFilter instanceof InputFilter.LengthFilter)) {
                        linkedList.add(inputFilter);
                    }
                }
                if (!linkedList.isEmpty()) {
                    inputFilterArr = (InputFilter[]) linkedList.toArray(new InputFilter[linkedList.size()]);
                }
            }
        } else if (filters.length > 0) {
            boolean z3 = false;
            for (int i3 = 0; i3 < filters.length; i3++) {
                if (filters[i3] instanceof InputFilter.LengthFilter) {
                    filters[i3] = new InputFilter.LengthFilter(num.intValue());
                    z3 = true;
                }
            }
            if (!z3) {
                InputFilter[] inputFilterArr2 = new InputFilter[filters.length + 1];
                System.arraycopy(filters, 0, inputFilterArr2, 0, filters.length);
                filters[filters.length] = new InputFilter.LengthFilter(num.intValue());
                filters = inputFilterArr2;
            }
            inputFilterArr = filters;
        } else {
            inputFilterArr = new InputFilter[]{new InputFilter.LengthFilter(num.intValue())};
        }
        c0493j.setFilters(inputFilterArr);
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "multiline")
    public void setMultiline(C0493j c0493j, boolean z3) {
        updateStagedInputTypeFlag(c0493j, z3 ? 0 : 131072, z3 ? 131072 : 0);
    }

    @K1.a(defaultInt = 1, name = "numberOfLines")
    public void setNumLines(C0493j c0493j, int i3) {
        c0493j.setLines(i3);
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "onContentSizeChange")
    public void setOnContentSizeChange(C0493j c0493j, boolean z3) {
        if (z3) {
            c0493j.setContentSizeWatcher(new b(c0493j));
        } else {
            c0493j.setContentSizeWatcher(null);
        }
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "onKeyPress")
    public void setOnKeyPress(C0493j c0493j, boolean z3) {
        c0493j.setOnKeyPress(z3);
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "onScroll")
    public void setOnScroll(C0493j c0493j, boolean z3) {
        if (z3) {
            c0493j.setScrollWatcher(new c(c0493j));
        } else {
            c0493j.setScrollWatcher(null);
        }
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "onSelectionChange")
    public void setOnSelectionChange(C0493j c0493j, boolean z3) {
        if (z3) {
            c0493j.setSelectionWatcher(new d(c0493j));
        } else {
            c0493j.setSelectionWatcher(null);
        }
    }

    @K1.a(name = "overflow")
    public void setOverflow(C0493j c0493j, String str) {
        c0493j.setOverflow(str);
    }

    @K1.a(name = "placeholder")
    public void setPlaceholder(C0493j c0493j, String str) {
        c0493j.setPlaceholder(str);
    }

    @K1.a(customType = "Color", name = "placeholderTextColor")
    public void setPlaceholderTextColor(C0493j c0493j, Integer num) {
        if (num == null) {
            c0493j.setHintTextColor(com.facebook.react.views.text.a.d(c0493j.getContext()));
        } else {
            c0493j.setHintTextColor(num.intValue());
        }
    }

    @K1.a(name = "returnKeyLabel")
    public void setReturnKeyLabel(C0493j c0493j, String str) {
        c0493j.setImeActionLabel(str, IME_ACTION_ID);
    }

    @K1.a(name = "returnKeyType")
    public void setReturnKeyType(C0493j c0493j, String str) {
        c0493j.setReturnKeyType(str);
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "secureTextEntry")
    public void setSecureTextEntry(C0493j c0493j, boolean z3) {
        updateStagedInputTypeFlag(c0493j, 144, z3 ? 128 : 0);
        checkPasswordType(c0493j);
    }

    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "selectTextOnFocus")
    public void setSelectTextOnFocus(C0493j c0493j, boolean z3) {
        c0493j.setSelectTextOnFocus(z3);
    }

    @K1.a(customType = "Color", name = "selectionColor")
    public void setSelectionColor(C0493j c0493j, Integer num) {
        if (num == null) {
            c0493j.setHighlightColor(com.facebook.react.views.text.a.c(c0493j.getContext()));
        } else {
            c0493j.setHighlightColor(num.intValue());
        }
    }

    @K1.a(customType = "Color", name = "selectionHandleColor")
    public void setSelectionHandleColor(C0493j c0493j, Integer num) {
        int i3;
        int i4 = Build.VERSION.SDK_INT;
        if (i4 >= 29) {
            Drawable drawableMutate = c0493j.getTextSelectHandle().mutate();
            Drawable drawableMutate2 = c0493j.getTextSelectHandleLeft().mutate();
            Drawable drawableMutate3 = c0493j.getTextSelectHandleRight().mutate();
            if (num != null) {
                com.facebook.react.uimanager.B.a();
                BlendModeColorFilter blendModeColorFilterA = AbstractC0480y.a(num.intValue(), BlendMode.SRC_IN);
                drawableMutate.setColorFilter(blendModeColorFilterA);
                drawableMutate2.setColorFilter(blendModeColorFilterA);
                drawableMutate3.setColorFilter(blendModeColorFilterA);
            } else {
                drawableMutate.clearColorFilter();
                drawableMutate2.clearColorFilter();
                drawableMutate3.clearColorFilter();
            }
            c0493j.setTextSelectHandle(drawableMutate);
            c0493j.setTextSelectHandleLeft(drawableMutate2);
            c0493j.setTextSelectHandleRight(drawableMutate3);
            return;
        }
        if (i4 == 28) {
            return;
        }
        int i5 = 0;
        while (true) {
            String[] strArr = DRAWABLE_HANDLE_RESOURCES;
            if (i5 >= strArr.length) {
                return;
            }
            try {
                Field declaredField = c0493j.getClass().getDeclaredField(strArr[i5]);
                declaredField.setAccessible(true);
                i3 = declaredField.getInt(c0493j);
            } catch (IllegalAccessException | NoSuchFieldException unused) {
            }
            if (i3 == 0) {
                return;
            }
            Drawable drawableMutate4 = androidx.core.content.a.d(c0493j.getContext(), i3).mutate();
            if (num != null) {
                drawableMutate4.setColorFilter(num.intValue(), PorterDuff.Mode.SRC_IN);
            } else {
                drawableMutate4.clearColorFilter();
            }
            Field declaredField2 = TextView.class.getDeclaredField("mEditor");
            declaredField2.setAccessible(true);
            Object obj = declaredField2.get(c0493j);
            Field declaredField3 = obj.getClass().getDeclaredField(DRAWABLE_HANDLE_FIELDS[i5]);
            declaredField3.setAccessible(true);
            declaredField3.set(obj, drawableMutate4);
            i5++;
        }
    }

    @K1.a(name = "submitBehavior")
    public void setSubmitBehavior(C0493j c0493j, String str) {
        c0493j.setSubmitBehavior(str);
    }

    @K1.a(name = "textAlign")
    public void setTextAlign(C0493j c0493j, String str) {
        if ("justify".equals(str)) {
            if (Build.VERSION.SDK_INT >= 26) {
                c0493j.setJustificationMode(1);
            }
            c0493j.setGravityHorizontal(SET_MOST_RECENT_EVENT_COUNT);
            return;
        }
        if (Build.VERSION.SDK_INT >= 26) {
            c0493j.setJustificationMode(0);
        }
        if (str == null || "auto".equals(str)) {
            c0493j.setGravityHorizontal(0);
            return;
        }
        if ("left".equals(str)) {
            c0493j.setGravityHorizontal(SET_MOST_RECENT_EVENT_COUNT);
            return;
        }
        if ("right".equals(str)) {
            c0493j.setGravityHorizontal(5);
            return;
        }
        if ("center".equals(str)) {
            c0493j.setGravityHorizontal(1);
            return;
        }
        Y.a.I("ReactNative", "Invalid textAlign: " + str);
        c0493j.setGravityHorizontal(0);
    }

    @K1.a(name = "textAlignVertical")
    public void setTextAlignVertical(C0493j c0493j, String str) {
        if (str == null || "auto".equals(str)) {
            c0493j.setGravityVertical(0);
            return;
        }
        if ("top".equals(str)) {
            c0493j.setGravityVertical(48);
            return;
        }
        if ("bottom".equals(str)) {
            c0493j.setGravityVertical(80);
            return;
        }
        if ("center".equals(str)) {
            c0493j.setGravityVertical(PASSWORD_VISIBILITY_FLAG);
            return;
        }
        Y.a.I("ReactNative", "Invalid textAlignVertical: " + str);
        c0493j.setGravityVertical(0);
    }

    @K1.a(name = "autoComplete")
    public void setTextContentType(C0493j c0493j, String str) {
        if (str == null) {
            setImportantForAutofill(c0493j, 2);
            return;
        }
        if ("off".equals(str)) {
            setImportantForAutofill(c0493j, 2);
            return;
        }
        Map<String, String> map = REACT_PROPS_AUTOFILL_HINTS_MAP;
        if (map.containsKey(str)) {
            setAutofillHints(c0493j, map.get(str));
            return;
        }
        Y.a.I("ReactNative", "Invalid autoComplete: " + str);
        setImportantForAutofill(c0493j, 2);
    }

    @K1.a(name = "textDecorationLine")
    public void setTextDecorationLine(C0493j c0493j, String str) {
        c0493j.setPaintFlags(c0493j.getPaintFlags() & (-25));
        if (str == null) {
            return;
        }
        for (String str2 : str.split(" ")) {
            if (str2.equals("underline")) {
                c0493j.setPaintFlags(c0493j.getPaintFlags() | 8);
            } else if (str2.equals("line-through")) {
                c0493j.setPaintFlags(c0493j.getPaintFlags() | PASSWORD_VISIBILITY_FLAG);
            }
        }
    }

    @K1.a(customType = "Color", name = "underlineColorAndroid")
    public void setUnderlineColor(C0493j c0493j, Integer num) {
        Drawable background = c0493j.getBackground();
        if (background == null) {
            return;
        }
        if (background.getConstantState() != null) {
            try {
                background = background.mutate();
            } catch (NullPointerException e3) {
                Y.a.n(TAG, "NullPointerException when setting underlineColorAndroid for TextInput", e3);
            }
        }
        if (num == null) {
            background.clearColorFilter();
        } else {
            background.setColorFilter(num.intValue(), PorterDuff.Mode.SRC_IN);
        }
    }

    @K1.a(defaultBoolean = true, name = "showSoftInputOnFocus")
    public void showKeyboardOnFocus(C0493j c0493j, boolean z3) {
        c0493j.setShowSoftInputOnFocus(z3);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public void addEventEmitters(final B0 b02, final C0493j c0493j) {
        c0493j.setEventDispatcher(getEventDispatcher(b02, c0493j));
        c0493j.addTextChangedListener(new e(b02, c0493j));
        c0493j.setOnFocusChangeListener(new View.OnFocusChangeListener() { // from class: com.facebook.react.views.textinput.E
            @Override // android.view.View.OnFocusChangeListener
            public final void onFocusChange(View view, boolean z3) {
                ReactTextInputManager.lambda$addEventEmitters$0(b02, c0493j, view, z3);
            }
        });
        c0493j.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: com.facebook.react.views.textinput.F
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i3, KeyEvent keyEvent) {
                return ReactTextInputManager.lambda$addEventEmitters$1(c0493j, b02, textView, i3, keyEvent);
            }
        });
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public com.facebook.react.views.text.c createShadowNodeInstance() {
        return new H();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public C0493j createViewInstance(B0 b02) {
        C0493j c0493j = new C0493j(b02);
        c0493j.setInputType(c0493j.getInputType() & (-131073));
        c0493j.setReturnKeyType("done");
        c0493j.setLayoutParams(new ViewGroup.LayoutParams(-2, -2));
        return c0493j;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public void onAfterUpdateTransaction(C0493j c0493j) {
        super.onAfterUpdateTransaction(c0493j);
        c0493j.Q();
        c0493j.y();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void setPadding(C0493j c0493j, int i3, int i4, int i5, int i6) {
        c0493j.setPadding(i3, i4, i5, i6);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void updateExtraData(C0493j c0493j, Object obj) {
        if (obj instanceof com.facebook.react.views.text.h) {
            com.facebook.react.views.text.h hVar = (com.facebook.react.views.text.h) obj;
            int iF = (int) hVar.f();
            int iH = (int) hVar.h();
            int iG = (int) hVar.g();
            int iE = (int) hVar.e();
            int length = UNSET;
            if (iF != UNSET || iH != UNSET || iG != UNSET || iE != UNSET) {
                if (iF == UNSET) {
                    iF = c0493j.getPaddingLeft();
                }
                if (iH == UNSET) {
                    iH = c0493j.getPaddingTop();
                }
                if (iG == UNSET) {
                    iG = c0493j.getPaddingRight();
                }
                if (iE == UNSET) {
                    iE = c0493j.getPaddingBottom();
                }
                c0493j.setPadding(iF, iH, iG, iE);
            }
            if (hVar.b()) {
                Y1.p.g(hVar.i(), c0493j);
            }
            if (c0493j.getSelectionStart() == c0493j.getSelectionEnd()) {
                length = hVar.i().length() - ((c0493j.getText() != null ? c0493j.getText().length() : 0) - c0493j.getSelectionStart());
            }
            c0493j.P(hVar);
            c0493j.M(hVar.c(), length, length);
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Object updateState(C0493j c0493j, C0469s0 c0469s0, A0 a02) {
        if (C0493j.f8227P) {
            Y.a.m(TAG, "updateState: [" + c0493j.getId() + "]");
        }
        if (c0493j.getStateWrapper() == null) {
            c0493j.setPadding(0, 0, 0, 0);
        }
        c0493j.setStateWrapper(a02);
        ReadableMapBuffer readableMapBufferE = a02.e();
        if (readableMapBufferE != null) {
            return getReactTextUpdate(c0493j, c0469s0, readableMapBufferE);
        }
        return null;
    }

    public com.facebook.react.views.text.c createShadowNodeInstance(com.facebook.react.views.text.n nVar) {
        return new H(nVar);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(C0493j c0493j, int i3, ReadableArray readableArray) {
        if (i3 == 1) {
            receiveCommand(c0493j, "focus", readableArray);
        } else if (i3 == 2) {
            receiveCommand(c0493j, "blur", readableArray);
        } else {
            if (i3 != SET_TEXT_AND_SELECTION) {
                return;
            }
            receiveCommand(c0493j, "setTextAndSelection", readableArray);
        }
    }

    public Object getReactTextUpdate(C0493j c0493j, C0469s0 c0469s0, com.facebook.react.common.mapbuffer.a aVar) {
        if (aVar.getCount() == 0) {
            return null;
        }
        com.facebook.react.common.mapbuffer.a aVarD = aVar.d(0);
        return com.facebook.react.views.text.h.a(com.facebook.react.views.text.s.g(c0493j.getContext(), aVarD, null), aVar.getInt(SET_MOST_RECENT_EVENT_COUNT), com.facebook.react.views.text.q.l(c0469s0, com.facebook.react.views.text.s.l(aVarD), c0493j.getGravityHorizontal()), com.facebook.react.views.text.q.m(aVar.d(1).getString(2)), com.facebook.react.views.text.q.h(c0469s0, Build.VERSION.SDK_INT >= 26 ? c0493j.getJustificationMode() : 0));
    }

    private void setImportantForAutofill(C0493j c0493j, int i3) {
        if (Build.VERSION.SDK_INT < 26) {
            return;
        }
        c0493j.setImportantForAutofill(i3);
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(C0493j c0493j, String str, ReadableArray readableArray) {
        byte b3;
        str.hashCode();
        switch (str.hashCode()) {
            case -1699362314:
                b3 = !str.equals("blurTextInput") ? UNSET : (byte) 0;
                break;
            case 3027047:
                b3 = !str.equals("blur") ? UNSET : (byte) 1;
                break;
            case 97604824:
                b3 = !str.equals("focus") ? UNSET : (byte) 2;
                break;
            case 1427010500:
                b3 = !str.equals("setTextAndSelection") ? UNSET : SET_MOST_RECENT_EVENT_COUNT;
                break;
            case 1690703013:
                b3 = !str.equals("focusTextInput") ? UNSET : (byte) 4;
                break;
            default:
                b3 = UNSET;
                break;
        }
        switch (b3) {
            case WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY /* 0 */:
            case 1:
                c0493j.x();
                break;
            case 2:
            case SET_TEXT_AND_SELECTION /* 4 */:
                c0493j.S();
                break;
            case SET_MOST_RECENT_EVENT_COUNT /* 3 */:
                int i3 = readableArray.getInt(0);
                if (i3 != UNSET) {
                    int i4 = readableArray.getInt(2);
                    int i5 = readableArray.getInt(SET_MOST_RECENT_EVENT_COUNT);
                    if (i5 == UNSET) {
                        i5 = i4;
                    }
                    if (!readableArray.isNull(1)) {
                        c0493j.O(getReactTextUpdate(readableArray.getString(1), i3));
                    }
                    c0493j.M(i3, i4, i5);
                    break;
                }
                break;
        }
    }
}
