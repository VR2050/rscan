package im.uwrkaxlmjj.ui.hui.contacts;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AddContactsActivity_ViewBinding implements Unbinder {
    private AddContactsActivity target;

    public AddContactsActivity_ViewBinding(AddContactsActivity target, View source) {
        this.target = target;
        target.searchView = (MrySearchView) Utils.findRequiredViewAsType(source, R.attr.searchView, "field 'searchView'", MrySearchView.class);
        target.rcvList = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.rcvList, "field 'rcvList'", RecyclerListView.class);
        target.tvSearchHeader = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvSearchHeader, "field 'tvSearchHeader'", TextView.class);
        target.tvSearchNumber = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvSearchNumber, "field 'tvSearchNumber'", TextView.class);
        target.llSearchLayout = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.llSearchLayout, "field 'llSearchLayout'", LinearLayout.class);
        target.searchLayout = (FrameLayout) Utils.findRequiredViewAsType(source, R.attr.searchLayout, "field 'searchLayout'", FrameLayout.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        AddContactsActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.searchView = null;
        target.rcvList = null;
        target.tvSearchHeader = null;
        target.tvSearchNumber = null;
        target.llSearchLayout = null;
        target.searchLayout = null;
    }
}
