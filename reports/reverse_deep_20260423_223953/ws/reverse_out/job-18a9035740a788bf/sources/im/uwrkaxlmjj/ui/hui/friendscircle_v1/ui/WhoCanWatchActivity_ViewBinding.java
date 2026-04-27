package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.view.View;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WhoCanWatchActivity_ViewBinding implements Unbinder {
    private WhoCanWatchActivity target;

    public WhoCanWatchActivity_ViewBinding(WhoCanWatchActivity target, View source) {
        this.target = target;
        target.rv = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.rv, "field 'rv'", RecyclerListView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        WhoCanWatchActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.rv = null;
    }
}
