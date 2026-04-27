package androidx.core.view;

import android.os.Bundle;
import android.text.style.ClickableSpan;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityNodeProvider;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.List;
import m.AbstractC0624b;
import r.v;

/* JADX INFO: renamed from: androidx.core.view.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0252a {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final View.AccessibilityDelegate f4440c = new View.AccessibilityDelegate();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final View.AccessibilityDelegate f4441a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final View.AccessibilityDelegate f4442b;

    /* JADX INFO: renamed from: androidx.core.view.a$a, reason: collision with other inner class name */
    static final class C0064a extends View.AccessibilityDelegate {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final C0252a f4443a;

        C0064a(C0252a c0252a) {
            this.f4443a = c0252a;
        }

        @Override // android.view.View.AccessibilityDelegate
        public boolean dispatchPopulateAccessibilityEvent(View view, AccessibilityEvent accessibilityEvent) {
            return this.f4443a.a(view, accessibilityEvent);
        }

        @Override // android.view.View.AccessibilityDelegate
        public AccessibilityNodeProvider getAccessibilityNodeProvider(View view) {
            r.w wVarB = this.f4443a.b(view);
            if (wVarB != null) {
                return (AccessibilityNodeProvider) wVarB.e();
            }
            return null;
        }

        @Override // android.view.View.AccessibilityDelegate
        public void onInitializeAccessibilityEvent(View view, AccessibilityEvent accessibilityEvent) {
            this.f4443a.f(view, accessibilityEvent);
        }

        @Override // android.view.View.AccessibilityDelegate
        public void onInitializeAccessibilityNodeInfo(View view, AccessibilityNodeInfo accessibilityNodeInfo) {
            r.v vVarQ0 = r.v.Q0(accessibilityNodeInfo);
            vVarQ0.G0(V.H(view));
            vVarQ0.x0(V.D(view));
            vVarQ0.B0(V.l(view));
            vVarQ0.L0(V.z(view));
            this.f4443a.g(view, vVarQ0);
            vVarQ0.f(accessibilityNodeInfo.getText(), view);
            List listC = C0252a.c(view);
            for (int i3 = 0; i3 < listC.size(); i3++) {
                vVarQ0.b((v.a) listC.get(i3));
            }
        }

        @Override // android.view.View.AccessibilityDelegate
        public void onPopulateAccessibilityEvent(View view, AccessibilityEvent accessibilityEvent) {
            this.f4443a.h(view, accessibilityEvent);
        }

        @Override // android.view.View.AccessibilityDelegate
        public boolean onRequestSendAccessibilityEvent(ViewGroup viewGroup, View view, AccessibilityEvent accessibilityEvent) {
            return this.f4443a.i(viewGroup, view, accessibilityEvent);
        }

        @Override // android.view.View.AccessibilityDelegate
        public boolean performAccessibilityAction(View view, int i3, Bundle bundle) {
            return this.f4443a.j(view, i3, bundle);
        }

        @Override // android.view.View.AccessibilityDelegate
        public void sendAccessibilityEvent(View view, int i3) {
            this.f4443a.l(view, i3);
        }

        @Override // android.view.View.AccessibilityDelegate
        public void sendAccessibilityEventUnchecked(View view, AccessibilityEvent accessibilityEvent) {
            this.f4443a.m(view, accessibilityEvent);
        }
    }

    public C0252a() {
        this(f4440c);
    }

    static List c(View view) {
        List list = (List) view.getTag(AbstractC0624b.f9533H);
        return list == null ? Collections.emptyList() : list;
    }

    private boolean e(ClickableSpan clickableSpan, View view) {
        if (clickableSpan != null) {
            ClickableSpan[] clickableSpanArrR = r.v.r(view.createAccessibilityNodeInfo().getText());
            for (int i3 = 0; clickableSpanArrR != null && i3 < clickableSpanArrR.length; i3++) {
                if (clickableSpan.equals(clickableSpanArrR[i3])) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean k(int i3, View view) {
        WeakReference weakReference;
        SparseArray sparseArray = (SparseArray) view.getTag(AbstractC0624b.f9534I);
        if (sparseArray == null || (weakReference = (WeakReference) sparseArray.get(i3)) == null) {
            return false;
        }
        ClickableSpan clickableSpan = (ClickableSpan) weakReference.get();
        if (!e(clickableSpan, view)) {
            return false;
        }
        clickableSpan.onClick(view);
        return true;
    }

    public boolean a(View view, AccessibilityEvent accessibilityEvent) {
        return this.f4441a.dispatchPopulateAccessibilityEvent(view, accessibilityEvent);
    }

    public r.w b(View view) {
        AccessibilityNodeProvider accessibilityNodeProvider = this.f4441a.getAccessibilityNodeProvider(view);
        if (accessibilityNodeProvider != null) {
            return new r.w(accessibilityNodeProvider);
        }
        return null;
    }

    View.AccessibilityDelegate d() {
        return this.f4442b;
    }

    public void f(View view, AccessibilityEvent accessibilityEvent) {
        this.f4441a.onInitializeAccessibilityEvent(view, accessibilityEvent);
    }

    public void g(View view, r.v vVar) {
        this.f4441a.onInitializeAccessibilityNodeInfo(view, vVar.P0());
    }

    public void h(View view, AccessibilityEvent accessibilityEvent) {
        this.f4441a.onPopulateAccessibilityEvent(view, accessibilityEvent);
    }

    public boolean i(ViewGroup viewGroup, View view, AccessibilityEvent accessibilityEvent) {
        return this.f4441a.onRequestSendAccessibilityEvent(viewGroup, view, accessibilityEvent);
    }

    public boolean j(View view, int i3, Bundle bundle) {
        List listC = c(view);
        boolean zPerformAccessibilityAction = false;
        int i4 = 0;
        while (true) {
            if (i4 >= listC.size()) {
                break;
            }
            v.a aVar = (v.a) listC.get(i4);
            if (aVar.a() == i3) {
                zPerformAccessibilityAction = aVar.c(view, bundle);
                break;
            }
            i4++;
        }
        if (!zPerformAccessibilityAction) {
            zPerformAccessibilityAction = this.f4441a.performAccessibilityAction(view, i3, bundle);
        }
        return (zPerformAccessibilityAction || i3 != AbstractC0624b.f9545a || bundle == null) ? zPerformAccessibilityAction : k(bundle.getInt("ACCESSIBILITY_CLICKABLE_SPAN_ID", -1), view);
    }

    public void l(View view, int i3) {
        this.f4441a.sendAccessibilityEvent(view, i3);
    }

    public void m(View view, AccessibilityEvent accessibilityEvent) {
        this.f4441a.sendAccessibilityEventUnchecked(view, accessibilityEvent);
    }

    public C0252a(View.AccessibilityDelegate accessibilityDelegate) {
        this.f4441a = accessibilityDelegate;
        this.f4442b = new C0064a(this);
    }
}
