package im.uwrkaxlmjj.ui.hui.contacts;

import android.view.View;
import android.widget.LinearLayout;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NewFriendsActivity_ViewBinding implements Unbinder {
    private NewFriendsActivity target;

    public NewFriendsActivity_ViewBinding(NewFriendsActivity target, View source) {
        this.target = target;
        target.listview = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.listview, "field 'listview'", RecyclerListView.class);
        target.progressBar = (RadialProgressView) Utils.findRequiredViewAsType(source, R.attr.progressBar, "field 'progressBar'", RadialProgressView.class);
        target.emptyLayout = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.emptyLayout, "field 'emptyLayout'", LinearLayout.class);
        target.tvEmptyText = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvEmptyText, "field 'tvEmptyText'", MryTextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        NewFriendsActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.listview = null;
        target.progressBar = null;
        target.emptyLayout = null;
        target.tvEmptyText = null;
    }
}
