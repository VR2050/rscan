package T1;

import android.view.View;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.AbstractC0445g;
import com.facebook.react.uimanager.BaseViewManager;

/* JADX INFO: loaded from: classes.dex */
public class k extends AbstractC0445g {
    public k(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.facebook.react.uimanager.AbstractC0445g, com.facebook.react.uimanager.Q0
    public void b(View view, String str, Object obj) {
        str.hashCode();
        switch (str) {
            case "presentationStyle":
                ((l) this.f7604a).setPresentationStyle(view, (String) obj);
                break;
            case "supportedOrientations":
                ((l) this.f7604a).setSupportedOrientations(view, (ReadableArray) obj);
                break;
            case "transparent":
                ((l) this.f7604a).setTransparent(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "identifier":
                ((l) this.f7604a).setIdentifier(view, obj != null ? ((Double) obj).intValue() : 0);
                break;
            case "statusBarTranslucent":
                ((l) this.f7604a).setStatusBarTranslucent(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "animated":
                ((l) this.f7604a).setAnimated(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "visible":
                ((l) this.f7604a).setVisible(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "navigationBarTranslucent":
                ((l) this.f7604a).setNavigationBarTranslucent(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "hardwareAccelerated":
                ((l) this.f7604a).setHardwareAccelerated(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "animationType":
                ((l) this.f7604a).setAnimationType(view, (String) obj);
                break;
            default:
                super.b(view, str, obj);
                break;
        }
    }
}
