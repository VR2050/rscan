package T1;

import android.view.View;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.AbstractC0445g;
import com.facebook.react.uimanager.BaseViewManager;

/* JADX INFO: loaded from: classes.dex */
public class i extends AbstractC0445g {
    public i(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.AbstractC0445g, com.facebook.react.uimanager.Q0
    public void a(View view, String str, ReadableArray readableArray) {
        str.hashCode();
        switch (str) {
            case "clearElementsHighlights":
                ((j) this.f7604a).clearElementsHighlights(view);
                break;
            case "highlightTraceUpdates":
                ((j) this.f7604a).highlightTraceUpdates(view, readableArray.getArray(0));
                break;
            case "highlightElements":
                ((j) this.f7604a).highlightElements(view, readableArray.getArray(0));
                break;
        }
    }

    @Override // com.facebook.react.uimanager.AbstractC0445g, com.facebook.react.uimanager.Q0
    public void b(View view, String str, Object obj) {
        super.b(view, str, obj);
    }
}
