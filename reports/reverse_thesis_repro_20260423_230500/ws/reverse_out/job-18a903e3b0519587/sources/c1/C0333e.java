package c1;

import com.facebook.react.bridge.ModuleSpec;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;
import com.facebook.react.views.debuggingoverlay.DebuggingOverlayManager;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.inject.Provider;
import v1.InterfaceC0708a;

/* JADX INFO: renamed from: c1.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0333e extends AbstractC0329a implements Y {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Map f5561a;

    /* JADX INFO: renamed from: c1.e$a */
    class a implements InterfaceC0708a {
        a() {
        }

        @Override // v1.InterfaceC0708a
        public Map a() {
            return Collections.emptyMap();
        }
    }

    private Map k() {
        if (this.f5561a == null) {
            HashMap map = new HashMap();
            map.put(DebuggingOverlayManager.REACT_CLASS, ModuleSpec.viewManagerSpec(new Provider() { // from class: c1.d
                @Override // javax.inject.Provider
                public final Object get() {
                    return new DebuggingOverlayManager();
                }
            }));
            this.f5561a = map;
        }
        return this.f5561a;
    }

    @Override // c1.Y
    public ViewManager a(ReactApplicationContext reactApplicationContext, String str) {
        ModuleSpec moduleSpec = (ModuleSpec) k().get(str);
        if (moduleSpec != null) {
            return (ViewManager) moduleSpec.getProvider().get();
        }
        return null;
    }

    @Override // c1.Y
    public Collection d(ReactApplicationContext reactApplicationContext) {
        return k().keySet();
    }

    @Override // c1.AbstractC0329a
    public NativeModule g(String str, ReactApplicationContext reactApplicationContext) {
        return null;
    }

    @Override // c1.AbstractC0329a
    public InterfaceC0708a i() {
        return new a();
    }

    @Override // c1.AbstractC0329a
    public List j(ReactApplicationContext reactApplicationContext) {
        return new ArrayList(k().values());
    }
}
