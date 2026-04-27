package com.facebook.react.views.textinput;

import android.R;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.KeyListener;
import android.text.method.QwertyKeyListener;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import androidx.appcompat.widget.C0238l;
import androidx.core.view.V;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.C0448h0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.UIManagerModule;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.uimanager.events.EventDispatcher;
import f1.C0527a;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import q1.C0655b;

/* JADX INFO: renamed from: com.facebook.react.views.textinput.j, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0493j extends C0238l {

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    public static final boolean f8227P;

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    private static final KeyListener f8228Q;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private com.facebook.react.views.text.r f8229A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private boolean f8230B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private String f8231C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private int f8232D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private int f8233E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private boolean f8234F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private boolean f8235G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private boolean f8236H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private boolean f8237I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private String f8238J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private Q1.p f8239K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    private A0 f8240L;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    protected boolean f8241M;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    protected boolean f8242N;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    private EventDispatcher f8243O;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final InputMethodManager f8244h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final String f8245i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    protected boolean f8246j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final int f8247k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final int f8248l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    protected int f8249m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private CopyOnWriteArrayList f8250n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private d f8251o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f8252p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    protected boolean f8253q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private String f8254r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f8255s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private String f8256t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private K f8257u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private InterfaceC0484a f8258v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private J f8259w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private c f8260x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private boolean f8261y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private boolean f8262z;

    /* JADX INFO: renamed from: com.facebook.react.views.textinput.j$a */
    class a extends C0448h0 {
        a(View view, boolean z3, int i3) {
            super(view, z3, i3);
        }

        @Override // com.facebook.react.uimanager.C0448h0, androidx.core.view.C0252a
        public boolean j(View view, int i3, Bundle bundle) {
            if (i3 != 16) {
                return super.j(view, i3, bundle);
            }
            int length = C0493j.this.getText().length();
            if (length > 0) {
                C0493j.this.setSelection(length);
            }
            return C0655b.o() ? C0493j.this.U() : C0493j.this.T();
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.views.textinput.j$b */
    class b implements ActionMode.Callback {
        b() {
        }

        @Override // android.view.ActionMode.Callback
        public boolean onActionItemClicked(ActionMode actionMode, MenuItem menuItem) {
            return false;
        }

        @Override // android.view.ActionMode.Callback
        public boolean onCreateActionMode(ActionMode actionMode, Menu menu) {
            if (C0493j.this.f8235G) {
                return false;
            }
            menu.removeItem(R.id.pasteAsPlainText);
            return true;
        }

        @Override // android.view.ActionMode.Callback
        public void onDestroyActionMode(ActionMode actionMode) {
        }

        @Override // android.view.ActionMode.Callback
        public boolean onPrepareActionMode(ActionMode actionMode, Menu menu) {
            return true;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.views.textinput.j$c */
    private static class c implements KeyListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f8265a = 0;

        public void a(int i3) {
            this.f8265a = i3;
        }

        @Override // android.text.method.KeyListener
        public void clearMetaKeyState(View view, Editable editable, int i3) {
            C0493j.f8228Q.clearMetaKeyState(view, editable, i3);
        }

        @Override // android.text.method.KeyListener
        public int getInputType() {
            return this.f8265a;
        }

        @Override // android.text.method.KeyListener
        public boolean onKeyDown(View view, Editable editable, int i3, KeyEvent keyEvent) {
            return C0493j.f8228Q.onKeyDown(view, editable, i3, keyEvent);
        }

        @Override // android.text.method.KeyListener
        public boolean onKeyOther(View view, Editable editable, KeyEvent keyEvent) {
            return C0493j.f8228Q.onKeyOther(view, editable, keyEvent);
        }

        @Override // android.text.method.KeyListener
        public boolean onKeyUp(View view, Editable editable, int i3, KeyEvent keyEvent) {
            return C0493j.f8228Q.onKeyUp(view, editable, i3, keyEvent);
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.views.textinput.j$d */
    private class d implements TextWatcher {
        @Override // android.text.TextWatcher
        public void afterTextChanged(Editable editable) {
            C0493j c0493j = C0493j.this;
            if (c0493j.f8246j || c0493j.f8250n == null) {
                return;
            }
            Iterator it = C0493j.this.f8250n.iterator();
            while (it.hasNext()) {
                ((TextWatcher) it.next()).afterTextChanged(editable);
            }
        }

        @Override // android.text.TextWatcher
        public void beforeTextChanged(CharSequence charSequence, int i3, int i4, int i5) {
            C0493j c0493j = C0493j.this;
            if (c0493j.f8246j || c0493j.f8250n == null) {
                return;
            }
            Iterator it = C0493j.this.f8250n.iterator();
            while (it.hasNext()) {
                ((TextWatcher) it.next()).beforeTextChanged(charSequence, i3, i4, i5);
            }
        }

        @Override // android.text.TextWatcher
        public void onTextChanged(CharSequence charSequence, int i3, int i4, int i5) {
            if (C0493j.f8227P) {
                Y.a.m(C0493j.this.f8245i, "onTextChanged[" + C0493j.this.getId() + "]: " + ((Object) charSequence) + " " + i3 + " " + i4 + " " + i5);
            }
            C0493j c0493j = C0493j.this;
            if (!c0493j.f8246j && c0493j.f8250n != null) {
                Iterator it = C0493j.this.f8250n.iterator();
                while (it.hasNext()) {
                    ((TextWatcher) it.next()).onTextChanged(charSequence, i3, i4, i5);
                }
            }
            C0493j.this.d0();
            C0493j.this.R();
        }

        private d() {
        }
    }

    static {
        C0527a c0527a = C0527a.f9197a;
        f8227P = false;
        f8228Q = QwertyKeyListener.getInstanceForFullKeyboard();
    }

    public C0493j(Context context) {
        super(context);
        this.f8245i = C0493j.class.getSimpleName();
        this.f8254r = null;
        this.f8261y = false;
        this.f8262z = false;
        this.f8230B = false;
        this.f8231C = null;
        this.f8232D = -1;
        this.f8233E = -1;
        this.f8234F = false;
        this.f8235G = false;
        this.f8236H = false;
        this.f8237I = false;
        this.f8238J = null;
        this.f8239K = Q1.p.f2499c;
        this.f8240L = null;
        this.f8241M = false;
        this.f8242N = false;
        if (!C0655b.o()) {
            setFocusableInTouchMode(false);
        }
        this.f8244h = (InputMethodManager) Z0.a.c(context.getSystemService("input_method"));
        this.f8247k = getGravity() & 8388615;
        this.f8248l = getGravity() & 112;
        this.f8249m = 0;
        this.f8246j = false;
        this.f8255s = false;
        this.f8250n = null;
        this.f8251o = null;
        this.f8252p = getInputType();
        if (this.f8260x == null) {
            this.f8260x = new c();
        }
        this.f8259w = null;
        this.f8229A = new com.facebook.react.views.text.r();
        u();
        int i3 = Build.VERSION.SDK_INT;
        if (i3 >= 26 && i3 <= 27) {
            setLayerType(1, null);
        }
        V.X(this, new a(this, isFocusable(), getImportantForAccessibility()));
        b bVar = new b();
        setCustomSelectionActionModeCallback(bVar);
        setCustomInsertionActionModeCallback(bVar);
    }

    private boolean C() {
        return (getInputType() & 144) != 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean D(Y1.d dVar) {
        return dVar.getSize() == this.f8229A.c();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean E(Y1.e eVar) {
        return Integer.valueOf(eVar.getBackgroundColor()).equals(C0433a.i(this));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean F(Y1.g gVar) {
        return gVar.getForegroundColor() == getCurrentTextColor();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean G(Y1.j jVar) {
        return (getPaintFlags() & 16) != 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean H(Y1.m mVar) {
        return (getPaintFlags() & 8) != 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean I(Y1.a aVar) {
        return aVar.b() == this.f8229A.d();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean J(Y1.c cVar) {
        return cVar.c() == this.f8233E && Objects.equals(cVar.a(), this.f8231C) && cVar.d() == this.f8232D && Objects.equals(cVar.b(), getFontFeatureSettings());
    }

    private void K(SpannableStringBuilder spannableStringBuilder) {
        for (Object obj : getText().getSpans(0, length(), Object.class)) {
            int spanFlags = getText().getSpanFlags(obj);
            boolean z3 = (spanFlags & 33) == 33;
            if (obj instanceof Y1.i) {
                getText().removeSpan(obj);
            }
            if (z3) {
                int spanStart = getText().getSpanStart(obj);
                int spanEnd = getText().getSpanEnd(obj);
                getText().removeSpan(obj);
                if (V(getText(), spannableStringBuilder, spanStart, spanEnd)) {
                    spannableStringBuilder.setSpan(obj, spanStart, spanEnd, spanFlags);
                }
            }
        }
    }

    private void L(int i3, int i4) {
        if (i3 == -1 || i4 == -1) {
            return;
        }
        setSelection(w(i3), w(i4));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void R() {
        InterfaceC0484a interfaceC0484a = this.f8258v;
        if (interfaceC0484a != null) {
            interfaceC0484a.a();
        }
        X();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean T() {
        setFocusableInTouchMode(true);
        boolean zRequestFocus = super.requestFocus(130, null);
        if (getShowSoftInputOnFocus()) {
            a0();
        }
        return zRequestFocus;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean U() {
        boolean zRequestFocus = super.requestFocus(130, null);
        if (isInTouchMode() && getShowSoftInputOnFocus()) {
            a0();
        }
        return zRequestFocus;
    }

    private static boolean V(Editable editable, SpannableStringBuilder spannableStringBuilder, int i3, int i4) {
        if (i3 > spannableStringBuilder.length() || i4 > spannableStringBuilder.length()) {
            return false;
        }
        while (i3 < i4) {
            if (editable.charAt(i3) != spannableStringBuilder.charAt(i3)) {
                return false;
            }
            i3++;
        }
        return true;
    }

    private void X() {
        ReactContext reactContextD = H0.d(this);
        if (this.f8240L != null || reactContextD.isBridgeless()) {
            return;
        }
        r rVar = new r(this);
        UIManagerModule uIManagerModule = (UIManagerModule) reactContextD.getNativeModule(UIManagerModule.class);
        if (uIManagerModule != null) {
            uIManagerModule.setViewLocalData(getId(), rVar);
        }
    }

    private void b0(SpannableStringBuilder spannableStringBuilder, Class cls, q.h hVar) {
        for (Object obj : spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), cls)) {
            if (hVar.a(obj)) {
                spannableStringBuilder.removeSpan(obj);
            }
        }
    }

    private void c0(SpannableStringBuilder spannableStringBuilder) {
        b0(spannableStringBuilder, Y1.d.class, new q.h() { // from class: com.facebook.react.views.textinput.c
            @Override // q.h
            public final boolean a(Object obj) {
                return this.f8220a.D((Y1.d) obj);
            }
        });
        b0(spannableStringBuilder, Y1.e.class, new q.h() { // from class: com.facebook.react.views.textinput.d
            @Override // q.h
            public final boolean a(Object obj) {
                return this.f8221a.E((Y1.e) obj);
            }
        });
        b0(spannableStringBuilder, Y1.g.class, new q.h() { // from class: com.facebook.react.views.textinput.e
            @Override // q.h
            public final boolean a(Object obj) {
                return this.f8222a.F((Y1.g) obj);
            }
        });
        b0(spannableStringBuilder, Y1.j.class, new q.h() { // from class: com.facebook.react.views.textinput.f
            @Override // q.h
            public final boolean a(Object obj) {
                return this.f8223a.G((Y1.j) obj);
            }
        });
        b0(spannableStringBuilder, Y1.m.class, new q.h() { // from class: com.facebook.react.views.textinput.g
            @Override // q.h
            public final boolean a(Object obj) {
                return this.f8224a.H((Y1.m) obj);
            }
        });
        b0(spannableStringBuilder, Y1.a.class, new q.h() { // from class: com.facebook.react.views.textinput.h
            @Override // q.h
            public final boolean a(Object obj) {
                return this.f8225a.I((Y1.a) obj);
            }
        });
        b0(spannableStringBuilder, Y1.c.class, new q.h() { // from class: com.facebook.react.views.textinput.i
            @Override // q.h
            public final boolean a(Object obj) {
                return this.f8226a.J((Y1.c) obj);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void d0() {
        if (this.f8240L == null || getId() == -1) {
            return;
        }
        Editable text = getText();
        boolean z3 = text != null && text.length() > 0;
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder();
        if (z3) {
            try {
                spannableStringBuilder.append(text.subSequence(0, text.length()));
            } catch (IndexOutOfBoundsException e3) {
                ReactSoftExceptionLogger.logSoftException(this.f8245i, e3);
            }
        }
        if (!z3) {
            if (getHint() != null && getHint().length() > 0) {
                spannableStringBuilder.append(getHint());
            } else if (L1.a.c(this) != 2) {
                spannableStringBuilder.append("I");
            }
        }
        t(spannableStringBuilder);
        spannableStringBuilder.setSpan(new Y1.l(new TextPaint(getPaint())), 0, spannableStringBuilder.length(), 18);
        com.facebook.react.views.text.s.o(getId(), spannableStringBuilder);
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:39:0x006a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void e0() {
        /*
            r9 = this;
            r0 = 5
            r1 = 4
            r2 = 3
            r3 = 2
            r4 = 1
            java.lang.String r5 = r9.f8256t
            r6 = 6
            if (r5 == 0) goto L6a
            r5.hashCode()
            r7 = -1
            int r8 = r5.hashCode()
            switch(r8) {
                case -1273775369: goto L58;
                case -906336856: goto L4d;
                case 3304: goto L42;
                case 3089282: goto L37;
                case 3377907: goto L2c;
                case 3387192: goto L21;
                case 3526536: goto L16;
                default: goto L15;
            }
        L15:
            goto L62
        L16:
            java.lang.String r8 = "send"
            boolean r5 = r5.equals(r8)
            if (r5 != 0) goto L1f
            goto L62
        L1f:
            r7 = r6
            goto L62
        L21:
            java.lang.String r8 = "none"
            boolean r5 = r5.equals(r8)
            if (r5 != 0) goto L2a
            goto L62
        L2a:
            r7 = r0
            goto L62
        L2c:
            java.lang.String r8 = "next"
            boolean r5 = r5.equals(r8)
            if (r5 != 0) goto L35
            goto L62
        L35:
            r7 = r1
            goto L62
        L37:
            java.lang.String r8 = "done"
            boolean r5 = r5.equals(r8)
            if (r5 != 0) goto L40
            goto L62
        L40:
            r7 = r2
            goto L62
        L42:
            java.lang.String r8 = "go"
            boolean r5 = r5.equals(r8)
            if (r5 != 0) goto L4b
            goto L62
        L4b:
            r7 = r3
            goto L62
        L4d:
            java.lang.String r8 = "search"
            boolean r5 = r5.equals(r8)
            if (r5 != 0) goto L56
            goto L62
        L56:
            r7 = r4
            goto L62
        L58:
            java.lang.String r8 = "previous"
            boolean r5 = r5.equals(r8)
            if (r5 != 0) goto L61
            goto L62
        L61:
            r7 = 0
        L62:
            switch(r7) {
                case 0: goto L70;
                case 1: goto L6e;
                case 2: goto L6c;
                case 3: goto L6a;
                case 4: goto L71;
                case 5: goto L68;
                case 6: goto L66;
                default: goto L65;
            }
        L65:
            goto L6a
        L66:
            r0 = r1
            goto L71
        L68:
            r0 = r4
            goto L71
        L6a:
            r0 = r6
            goto L71
        L6c:
            r0 = r3
            goto L71
        L6e:
            r0 = r2
            goto L71
        L70:
            r0 = 7
        L71:
            boolean r1 = r9.f8255s
            if (r1 == 0) goto L7c
            r1 = 33554432(0x2000000, float:9.403955E-38)
            r0 = r0 | r1
            r9.setImeOptions(r0)
            goto L7f
        L7c:
            r9.setImeOptions(r0)
        L7f:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.views.textinput.C0493j.e0():void");
    }

    private d getTextWatcherDelegator() {
        if (this.f8251o == null) {
            this.f8251o = new d();
        }
        return this.f8251o;
    }

    private void t(SpannableStringBuilder spannableStringBuilder) {
        spannableStringBuilder.setSpan(new Y1.d(this.f8229A.c()), 0, spannableStringBuilder.length(), 16711698);
        spannableStringBuilder.setSpan(new Y1.g(getCurrentTextColor()), 0, spannableStringBuilder.length(), 16711698);
        Integer numI = C0433a.i(this);
        if (numI != null && numI.intValue() != 0) {
            spannableStringBuilder.setSpan(new Y1.e(numI.intValue()), 0, spannableStringBuilder.length(), 16711698);
        }
        if ((getPaintFlags() & 16) != 0) {
            spannableStringBuilder.setSpan(new Y1.j(), 0, spannableStringBuilder.length(), 16711698);
        }
        if ((getPaintFlags() & 8) != 0) {
            spannableStringBuilder.setSpan(new Y1.m(), 0, spannableStringBuilder.length(), 16711698);
        }
        float fD = this.f8229A.d();
        if (!Float.isNaN(fD)) {
            spannableStringBuilder.setSpan(new Y1.a(fD), 0, spannableStringBuilder.length(), 16711698);
        }
        if (this.f8233E != -1 || this.f8232D != -1 || this.f8231C != null || getFontFeatureSettings() != null) {
            spannableStringBuilder.setSpan(new Y1.c(this.f8233E, this.f8232D, getFontFeatureSettings(), this.f8231C, getContext().getAssets()), 0, spannableStringBuilder.length(), 16711698);
        }
        float fE = this.f8229A.e();
        if (Float.isNaN(fE)) {
            return;
        }
        spannableStringBuilder.setSpan(new Y1.b(fE), 0, spannableStringBuilder.length(), 16711698);
    }

    private int w(int i3) {
        return Math.max(0, Math.min(i3, getText() == null ? 0 : getText().length()));
    }

    public int A() {
        int i3 = this.f8249m + 1;
        this.f8249m = i3;
        return i3;
    }

    boolean B() {
        return (getInputType() & 131072) != 0;
    }

    public void M(int i3, int i4, int i5) {
        if (v(i3)) {
            L(i4, i5);
        }
    }

    public void N(com.facebook.react.views.text.h hVar) {
        if (!(C() && TextUtils.equals(getText(), hVar.i())) && v(hVar.c())) {
            if (f8227P) {
                Y.a.m(this.f8245i, "maybeSetText[" + getId() + "]: current text: " + ((Object) getText()) + " update: " + ((Object) hVar.i()));
            }
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(hVar.i());
            K(spannableStringBuilder);
            c0(spannableStringBuilder);
            this.f8253q = hVar.b();
            this.f8241M = true;
            if (hVar.i().length() == 0) {
                setText((CharSequence) null);
            } else {
                getText().replace(0, length(), spannableStringBuilder);
            }
            this.f8241M = false;
            if (getBreakStrategy() != hVar.k()) {
                setBreakStrategy(hVar.k());
            }
            d0();
        }
    }

    public void O(com.facebook.react.views.text.h hVar) {
        this.f8246j = true;
        N(hVar);
        this.f8246j = false;
    }

    public void P(com.facebook.react.views.text.h hVar) {
        this.f8242N = true;
        N(hVar);
        this.f8242N = false;
    }

    public void Q() {
        if (this.f8230B) {
            this.f8230B = false;
            setTypeface(com.facebook.react.views.text.o.a(getTypeface(), this.f8233E, this.f8232D, this.f8231C, getContext().getAssets()));
            if (this.f8233E == -1 && this.f8232D == -1 && this.f8231C == null && getFontFeatureSettings() == null) {
                setPaintFlags(getPaintFlags() & (-129));
            } else {
                setPaintFlags(getPaintFlags() | 128);
            }
        }
    }

    public void S() {
        if (C0655b.o()) {
            U();
        } else {
            T();
        }
    }

    public void W(float f3, int i3) {
        C0433a.q(this, Q1.d.values()[i3], Float.isNaN(f3) ? null : new W(C0444f0.f(f3), X.f7535b));
    }

    public boolean Y() {
        String submitBehavior = getSubmitBehavior();
        return submitBehavior == null ? !B() : submitBehavior.equals("blurAndSubmit");
    }

    public boolean Z() {
        String submitBehavior = getSubmitBehavior();
        if (submitBehavior == null) {
            if (B()) {
                return false;
            }
        } else if (!submitBehavior.equals("submit") && !submitBehavior.equals("blurAndSubmit")) {
            return false;
        }
        return true;
    }

    protected boolean a0() {
        return this.f8244h.showSoftInput(this, 0);
    }

    @Override // android.widget.TextView
    public void addTextChangedListener(TextWatcher textWatcher) {
        if (this.f8250n == null) {
            this.f8250n = new CopyOnWriteArrayList();
            super.addTextChangedListener(getTextWatcherDelegator());
        }
        this.f8250n.add(textWatcher);
    }

    @Override // android.view.View
    public void clearFocus() {
        if (!C0655b.o()) {
            setFocusableInTouchMode(false);
        }
        super.clearFocus();
        z();
    }

    protected void finalize() {
        if (f8227P) {
            Y.a.m(this.f8245i, "finalize[" + getId() + "] delete cached spannable");
        }
        com.facebook.react.views.text.s.f(getId());
    }

    public boolean getDisableFullscreenUI() {
        return this.f8255s;
    }

    int getGravityHorizontal() {
        return getGravity() & 8388615;
    }

    public String getReturnKeyType() {
        return this.f8256t;
    }

    int getStagedInputType() {
        return this.f8252p;
    }

    public A0 getStateWrapper() {
        return this.f8240L;
    }

    public String getSubmitBehavior() {
        return this.f8254r;
    }

    @Override // android.widget.TextView, android.view.View, android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable drawable) {
        if (this.f8253q) {
            Editable text = getText();
            for (Y1.p pVar : (Y1.p[]) text.getSpans(0, text.length(), Y1.p.class)) {
                if (pVar.a() == drawable) {
                    invalidate();
                }
            }
        }
        super.invalidateDrawable(drawable);
    }

    @Override // android.view.View
    public boolean isLayoutRequested() {
        return false;
    }

    @Override // android.widget.TextView, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        int selectionStart = getSelectionStart();
        int selectionEnd = getSelectionEnd();
        super.setTextIsSelectable(true);
        L(selectionStart, selectionEnd);
        if (this.f8253q) {
            Editable text = getText();
            for (Y1.p pVar : (Y1.p[]) text.getSpans(0, text.length(), Y1.p.class)) {
                pVar.c();
            }
        }
        if (this.f8234F && !this.f8236H) {
            if (C0655b.o()) {
                U();
            } else {
                T();
            }
        }
        this.f8236H = true;
    }

    @Override // androidx.appcompat.widget.C0238l, android.widget.TextView, android.view.View
    public InputConnection onCreateInputConnection(EditorInfo editorInfo) {
        ReactContext reactContextD = H0.d(this);
        InputConnection inputConnectionOnCreateInputConnection = super.onCreateInputConnection(editorInfo);
        if (inputConnectionOnCreateInputConnection != null && this.f8262z) {
            inputConnectionOnCreateInputConnection = new l(inputConnectionOnCreateInputConnection, reactContextD, this, this.f8243O);
        }
        if (B() && (Y() || Z())) {
            editorInfo.imeOptions &= -1073741825;
        }
        return inputConnectionOnCreateInputConnection;
    }

    @Override // androidx.appcompat.widget.C0238l, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.f8253q) {
            Editable text = getText();
            for (Y1.p pVar : (Y1.p[]) text.getSpans(0, text.length(), Y1.p.class)) {
                pVar.d();
            }
        }
    }

    @Override // android.widget.TextView, android.view.View
    public void onDraw(Canvas canvas) {
        if (this.f8239K != Q1.p.f2499c) {
            C0433a.a(this, canvas);
        }
        super.onDraw(canvas);
    }

    @Override // android.view.View
    public void onFinishTemporaryDetach() {
        super.onFinishTemporaryDetach();
        if (this.f8253q) {
            Editable text = getText();
            for (Y1.p pVar : (Y1.p[]) text.getSpans(0, text.length(), Y1.p.class)) {
                pVar.e();
            }
        }
    }

    @Override // android.widget.TextView, android.view.View
    protected void onFocusChanged(boolean z3, int i3, Rect rect) {
        K k3;
        super.onFocusChanged(z3, i3, rect);
        if (!z3 || (k3 = this.f8257u) == null) {
            return;
        }
        k3.a(getSelectionStart(), getSelectionEnd());
    }

    @Override // android.widget.TextView, android.view.View, android.view.KeyEvent.Callback
    public boolean onKeyUp(int i3, KeyEvent keyEvent) {
        if (i3 != 66 || B()) {
            return super.onKeyUp(i3, keyEvent);
        }
        z();
        return true;
    }

    @Override // android.widget.TextView, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        R();
        if (this.f8237I && isFocused()) {
            selectAll();
            this.f8237I = false;
        }
    }

    @Override // android.widget.TextView, android.view.View
    protected void onScrollChanged(int i3, int i4, int i5, int i6) {
        super.onScrollChanged(i3, i4, i5, i6);
        J j3 = this.f8259w;
        if (j3 != null) {
            j3.a(i3, i4, i5, i6);
        }
    }

    @Override // android.widget.TextView
    protected void onSelectionChanged(int i3, int i4) {
        if (f8227P) {
            Y.a.m(this.f8245i, "onSelectionChanged[" + getId() + "]: " + i3 + " " + i4);
        }
        super.onSelectionChanged(i3, i4);
        if (this.f8257u == null || !hasFocus()) {
            return;
        }
        this.f8257u.a(i3, i4);
    }

    @Override // android.view.View
    public void onStartTemporaryDetach() {
        super.onStartTemporaryDetach();
        if (this.f8253q) {
            Editable text = getText();
            for (Y1.p pVar : (Y1.p[]) text.getSpans(0, text.length(), Y1.p.class)) {
                pVar.f();
            }
        }
    }

    @Override // androidx.appcompat.widget.C0238l, android.widget.EditText, android.widget.TextView
    public boolean onTextContextMenuItem(int i3) {
        if (i3 == 16908322) {
            i3 = R.id.pasteAsPlainText;
        }
        return super.onTextContextMenuItem(i3);
    }

    @Override // android.widget.TextView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        int action = motionEvent.getAction();
        if (action == 0) {
            this.f8261y = true;
            getParent().requestDisallowInterceptTouchEvent(true);
        } else if (action == 2 && this.f8261y) {
            if (!canScrollVertically(-1) && !canScrollVertically(1) && !canScrollHorizontally(-1) && !canScrollHorizontally(1)) {
                getParent().requestDisallowInterceptTouchEvent(false);
            }
            this.f8261y = false;
        }
        return super.onTouchEvent(motionEvent);
    }

    @Override // android.widget.TextView
    public void removeTextChangedListener(TextWatcher textWatcher) {
        CopyOnWriteArrayList copyOnWriteArrayList = this.f8250n;
        if (copyOnWriteArrayList != null) {
            copyOnWriteArrayList.remove(textWatcher);
            if (this.f8250n.isEmpty()) {
                this.f8250n = null;
                super.removeTextChangedListener(getTextWatcherDelegator());
            }
        }
    }

    @Override // android.view.View
    public boolean requestFocus(int i3, Rect rect) {
        return C0655b.o() ? super.requestFocus(i3, rect) : isFocused();
    }

    public void setAllowFontScaling(boolean z3) {
        if (this.f8229A.b() != z3) {
            this.f8229A.m(z3);
            u();
        }
    }

    public void setAutoFocus(boolean z3) {
        this.f8234F = z3;
    }

    @Override // android.view.View
    public void setBackgroundColor(int i3) {
        C0433a.n(this, Integer.valueOf(i3));
    }

    public void setBorderRadius(float f3) {
        W(f3, Q1.d.f2402b.ordinal());
    }

    public void setBorderStyle(String str) {
        C0433a.r(this, str == null ? null : Q1.f.b(str));
    }

    public void setContentSizeWatcher(InterfaceC0484a interfaceC0484a) {
        this.f8258v = interfaceC0484a;
    }

    public void setContextMenuHidden(boolean z3) {
        this.f8235G = z3;
    }

    public void setDisableFullscreenUI(boolean z3) {
        this.f8255s = z3;
        e0();
    }

    void setEventDispatcher(EventDispatcher eventDispatcher) {
        this.f8243O = eventDispatcher;
    }

    public void setFontFamily(String str) {
        this.f8231C = str;
        this.f8230B = true;
    }

    @Override // android.widget.TextView
    public void setFontFeatureSettings(String str) {
        if (Objects.equals(str, getFontFeatureSettings())) {
            return;
        }
        super.setFontFeatureSettings(str);
        this.f8230B = true;
    }

    public void setFontSize(float f3) {
        this.f8229A.n(f3);
        u();
    }

    public void setFontStyle(String str) {
        int iB = com.facebook.react.views.text.o.b(str);
        if (iB != this.f8233E) {
            this.f8233E = iB;
            this.f8230B = true;
        }
    }

    public void setFontWeight(String str) {
        int iD = com.facebook.react.views.text.o.d(str);
        if (iD != this.f8232D) {
            this.f8232D = iD;
            this.f8230B = true;
        }
    }

    void setGravityHorizontal(int i3) {
        if (i3 == 0) {
            i3 = this.f8247k;
        }
        setGravity(i3 | (getGravity() & (-8388616)));
    }

    void setGravityVertical(int i3) {
        if (i3 == 0) {
            i3 = this.f8248l;
        }
        setGravity(i3 | (getGravity() & (-113)));
    }

    @Override // android.widget.TextView
    public void setInputType(int i3) {
        Typeface typeface = super.getTypeface();
        super.setInputType(i3);
        this.f8252p = i3;
        super.setTypeface(typeface);
        if (B()) {
            setSingleLine(false);
        }
        if (this.f8260x == null) {
            this.f8260x = new c();
        }
        this.f8260x.a(i3);
        setKeyListener(this.f8260x);
    }

    public void setLetterSpacingPt(float f3) {
        this.f8229A.p(f3);
        u();
    }

    @Override // android.widget.TextView
    public void setLineHeight(int i3) {
        this.f8229A.q(i3);
    }

    public void setMaxFontSizeMultiplier(float f3) {
        if (f3 != this.f8229A.k()) {
            this.f8229A.r(f3);
            u();
        }
    }

    public void setOnKeyPress(boolean z3) {
        this.f8262z = z3;
    }

    public void setOverflow(String str) {
        if (str == null) {
            this.f8239K = Q1.p.f2499c;
        } else {
            Q1.p pVarB = Q1.p.b(str);
            if (pVarB == null) {
                pVarB = Q1.p.f2499c;
            }
            this.f8239K = pVarB;
        }
        invalidate();
    }

    public void setPlaceholder(String str) {
        if (Objects.equals(str, this.f8238J)) {
            return;
        }
        this.f8238J = str;
        setHint(str);
    }

    public void setReturnKeyType(String str) {
        this.f8256t = str;
        e0();
    }

    public void setScrollWatcher(J j3) {
        this.f8259w = j3;
    }

    public void setSelectTextOnFocus(boolean z3) {
        super.setSelectAllOnFocus(z3);
        this.f8237I = z3;
    }

    @Override // android.widget.EditText
    public void setSelection(int i3, int i4) {
        if (f8227P) {
            Y.a.m(this.f8245i, "setSelection[" + getId() + "]: " + i3 + " " + i4);
        }
        super.setSelection(i3, i4);
    }

    public void setSelectionWatcher(K k3) {
        this.f8257u = k3;
    }

    void setStagedInputType(int i3) {
        this.f8252p = i3;
    }

    public void setStateWrapper(A0 a02) {
        this.f8240L = a02;
    }

    public void setSubmitBehavior(String str) {
        this.f8254r = str;
    }

    protected void u() {
        setTextSize(0, this.f8229A.c());
        float fD = this.f8229A.d();
        if (Float.isNaN(fD)) {
            return;
        }
        setLetterSpacing(fD);
    }

    public boolean v(int i3) {
        return i3 >= this.f8249m;
    }

    @Override // android.widget.TextView, android.view.View
    protected boolean verifyDrawable(Drawable drawable) {
        if (this.f8253q) {
            Editable text = getText();
            for (Y1.p pVar : (Y1.p[]) text.getSpans(0, text.length(), Y1.p.class)) {
                if (pVar.a() == drawable) {
                    return true;
                }
            }
        }
        return super.verifyDrawable(drawable);
    }

    void x() {
        clearFocus();
    }

    void y() {
        if (getInputType() != this.f8252p) {
            int selectionStart = getSelectionStart();
            int selectionEnd = getSelectionEnd();
            setInputType(this.f8252p);
            L(selectionStart, selectionEnd);
        }
    }

    protected void z() {
        this.f8244h.hideSoftInputFromWindow(getWindowToken(), 0);
    }
}
