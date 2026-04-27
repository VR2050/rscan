package im.uwrkaxlmjj.ui.hui.packet;

import android.view.View;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktGroupDetailActivity_ViewBinding implements Unbinder {
    private RedpktGroupDetailActivity target;

    public RedpktGroupDetailActivity_ViewBinding(RedpktGroupDetailActivity target, View source) {
        this.target = target;
        target.rcyRpkHistory = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.rcy_rpk_history, "field 'rcyRpkHistory'", RecyclerListView.class);
        target.tvRpkBackDesc = (TextView) Utils.findRequiredViewAsType(source, R.attr.tv_rpk_back_desc, "field 'tvRpkBackDesc'", TextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        RedpktGroupDetailActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.rcyRpkHistory = null;
        target.tvRpkBackDesc = null;
    }
}
