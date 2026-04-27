package r;

import android.os.Build;
import android.os.Bundle;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityNodeProvider;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class w {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Object f9980a;

    static class a extends AccessibilityNodeProvider {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final w f9981a;

        a(w wVar) {
            this.f9981a = wVar;
        }

        @Override // android.view.accessibility.AccessibilityNodeProvider
        public AccessibilityNodeInfo createAccessibilityNodeInfo(int i3) {
            v vVarB = this.f9981a.b(i3);
            if (vVarB == null) {
                return null;
            }
            return vVarB.P0();
        }

        @Override // android.view.accessibility.AccessibilityNodeProvider
        public List findAccessibilityNodeInfosByText(String str, int i3) {
            List listC = this.f9981a.c(str, i3);
            if (listC == null) {
                return null;
            }
            ArrayList arrayList = new ArrayList();
            int size = listC.size();
            for (int i4 = 0; i4 < size; i4++) {
                arrayList.add(((v) listC.get(i4)).P0());
            }
            return arrayList;
        }

        @Override // android.view.accessibility.AccessibilityNodeProvider
        public AccessibilityNodeInfo findFocus(int i3) {
            v vVarD = this.f9981a.d(i3);
            if (vVarD == null) {
                return null;
            }
            return vVarD.P0();
        }

        @Override // android.view.accessibility.AccessibilityNodeProvider
        public boolean performAction(int i3, int i4, Bundle bundle) {
            return this.f9981a.f(i3, i4, bundle);
        }
    }

    static class b extends a {
        b(w wVar) {
            super(wVar);
        }

        @Override // android.view.accessibility.AccessibilityNodeProvider
        public void addExtraDataToAccessibilityNodeInfo(int i3, AccessibilityNodeInfo accessibilityNodeInfo, String str, Bundle bundle) {
            this.f9981a.a(i3, v.Q0(accessibilityNodeInfo), str, bundle);
        }
    }

    public w() {
        if (Build.VERSION.SDK_INT >= 26) {
            this.f9980a = new b(this);
        } else {
            this.f9980a = new a(this);
        }
    }

    public v b(int i3) {
        return null;
    }

    public List c(String str, int i3) {
        return null;
    }

    public v d(int i3) {
        return null;
    }

    public Object e() {
        return this.f9980a;
    }

    public boolean f(int i3, int i4, Bundle bundle) {
        return false;
    }

    public w(Object obj) {
        this.f9980a = obj;
    }

    public void a(int i3, v vVar, String str, Bundle bundle) {
    }
}
