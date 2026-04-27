package c1;

import c2.C0353a;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.react.devsupport.LogBoxModule;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.modules.core.ExceptionsManagerModule;
import com.facebook.react.modules.core.HeadlessJsTaskSupportModule;
import com.facebook.react.modules.core.TimingModule;
import com.facebook.react.modules.debug.DevMenuModule;
import com.facebook.react.modules.debug.DevSettingsModule;
import com.facebook.react.modules.debug.SourceCodeModule;
import com.facebook.react.modules.deviceinfo.DeviceInfoModule;
import com.facebook.react.modules.systeminfo.AndroidInfoModule;
import com.facebook.react.uimanager.UIManagerModule;
import com.facebook.react.uimanager.V0;
import com.facebook.react.uimanager.ViewManager;
import d1.C0505a;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import u1.InterfaceC0703a;
import v1.InterfaceC0708a;

/* JADX INFO: renamed from: c1.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0331c extends AbstractC0329a implements N {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final G f5556a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final A1.a f5557b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f5558c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f5559d;

    /* JADX INFO: renamed from: c1.c$a */
    class a implements V0 {
        a() {
        }

        @Override // com.facebook.react.uimanager.V0
        public ViewManager a(String str) {
            return C0331c.this.f5556a.z(str);
        }

        @Override // com.facebook.react.uimanager.V0
        public Collection b() {
            return C0331c.this.f5556a.H();
        }
    }

    public C0331c(G g3, A1.a aVar, boolean z3, int i3) {
        this.f5556a = g3;
        this.f5557b = aVar;
        this.f5558c = z3;
        this.f5559d = i3;
    }

    private UIManagerModule m(ReactApplicationContext reactApplicationContext) {
        ReactMarker.logMarker(ReactMarkerConstants.CREATE_UI_MANAGER_MODULE_START);
        C0353a.c(0L, "createUIManagerModule");
        try {
            return this.f5558c ? new UIManagerModule(reactApplicationContext, new a(), this.f5559d) : new UIManagerModule(reactApplicationContext, (List<ViewManager>) this.f5556a.G(reactApplicationContext), this.f5559d);
        } finally {
            C0353a.i(0L);
            ReactMarker.logMarker(ReactMarkerConstants.CREATE_UI_MANAGER_MODULE_END);
        }
    }

    private InterfaceC0708a n() {
        Class[] clsArr = {AndroidInfoModule.class, DeviceEventManagerModule.class, DeviceInfoModule.class, DevMenuModule.class, DevSettingsModule.class, ExceptionsManagerModule.class, LogBoxModule.class, HeadlessJsTaskSupportModule.class, SourceCodeModule.class, TimingModule.class, UIManagerModule.class};
        final HashMap map = new HashMap();
        for (int i3 = 0; i3 < 11; i3++) {
            Class cls = clsArr[i3];
            InterfaceC0703a interfaceC0703a = (InterfaceC0703a) cls.getAnnotation(InterfaceC0703a.class);
            map.put(interfaceC0703a.name(), new ReactModuleInfo(interfaceC0703a.name(), cls.getName(), interfaceC0703a.canOverrideExistingModule(), interfaceC0703a.needsEagerInit(), interfaceC0703a.isCxxModule(), ReactModuleInfo.b(cls)));
        }
        return new InterfaceC0708a() { // from class: c1.b
            @Override // v1.InterfaceC0708a
            public final Map a() {
                return C0331c.o(map);
            }
        };
    }

    @Override // c1.N
    public void b() {
        ReactMarker.logMarker(ReactMarkerConstants.PROCESS_CORE_REACT_PACKAGE_START);
    }

    @Override // c1.N
    public void c() {
        ReactMarker.logMarker(ReactMarkerConstants.PROCESS_CORE_REACT_PACKAGE_END);
    }

    @Override // c1.AbstractC0329a
    public NativeModule g(String str, ReactApplicationContext reactApplicationContext) {
        str.hashCode();
        switch (str) {
            case "LogBox":
                return new LogBoxModule(reactApplicationContext, this.f5556a.D());
            case "Timing":
                return new TimingModule(reactApplicationContext, this.f5556a.D());
            case "DevSettings":
                return new DevSettingsModule(reactApplicationContext, this.f5556a.D());
            case "DeviceInfo":
                return new DeviceInfoModule(reactApplicationContext);
            case "DevMenu":
                return new DevMenuModule(reactApplicationContext, this.f5556a.D());
            case "DeviceEventManager":
                return new DeviceEventManagerModule(reactApplicationContext, this.f5557b);
            case "PlatformConstants":
                return new AndroidInfoModule(reactApplicationContext);
            case "ExceptionsManager":
                return new ExceptionsManagerModule(this.f5556a.D());
            case "SourceCode":
                return new SourceCodeModule(reactApplicationContext);
            case "HeadlessJsTaskSupport":
                return new HeadlessJsTaskSupportModule(reactApplicationContext);
            case "UIManager":
                return m(reactApplicationContext);
            default:
                throw new IllegalArgumentException("In CoreModulesPackage, could not find Native module for " + str);
        }
    }

    @Override // c1.AbstractC0329a
    public InterfaceC0708a i() {
        if (!C0505a.a()) {
            return n();
        }
        try {
            return (InterfaceC0708a) C0505a.b("com.facebook.react.CoreModulesPackage$$ReactModuleInfoProvider").newInstance();
        } catch (ClassNotFoundException unused) {
            return n();
        } catch (IllegalAccessException e3) {
            throw new RuntimeException("No ReactModuleInfoProvider for CoreModulesPackage$$ReactModuleInfoProvider", e3);
        } catch (InstantiationException e4) {
            throw new RuntimeException("No ReactModuleInfoProvider for CoreModulesPackage$$ReactModuleInfoProvider", e4);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ Map o(Map map) {
        return map;
    }
}
