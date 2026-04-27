package T1;

import android.view.View;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.uimanager.AbstractC0445g;
import com.facebook.react.uimanager.BaseViewManager;

/* JADX INFO: loaded from: classes.dex */
public class c extends AbstractC0445g {
    public c(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.AbstractC0445g, com.facebook.react.uimanager.Q0
    public void b(View view, String str, Object obj) {
        str.hashCode();
        switch (str) {
            case "progress":
                ((d) this.f7604a).setProgress(view, obj == null ? 0.0d : ((Double) obj).doubleValue());
                break;
            case "testID":
                ((d) this.f7604a).setTestID(view, obj == null ? "" : (String) obj);
                break;
            case "typeAttr":
                ((d) this.f7604a).setTypeAttr(view, obj != null ? (String) obj : null);
                break;
            case "color":
                ((d) this.f7604a).setColor(view, ColorPropConverter.getColor(obj, view.getContext()));
                break;
            case "indeterminate":
                ((d) this.f7604a).setIndeterminate(view, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "animating":
                ((d) this.f7604a).setAnimating(view, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "styleAttr":
                ((d) this.f7604a).setStyleAttr(view, obj != null ? (String) obj : null);
                break;
            default:
                super.b(view, str, obj);
                break;
        }
    }
}
