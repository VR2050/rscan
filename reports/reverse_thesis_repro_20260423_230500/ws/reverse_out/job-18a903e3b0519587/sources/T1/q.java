package T1;

import android.view.View;
import com.facebook.react.uimanager.AbstractC0445g;
import com.facebook.react.uimanager.BaseViewManager;

/* JADX INFO: loaded from: classes.dex */
public class q extends AbstractC0445g {
    public q(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.AbstractC0445g, com.facebook.react.uimanager.Q0
    public void b(View view, String str, Object obj) {
        str.hashCode();
        if (str.equals("name")) {
            ((r) this.f7604a).setName(view, obj == null ? "" : (String) obj);
        } else {
            super.b(view, str, obj);
        }
    }
}
