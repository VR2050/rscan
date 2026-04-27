package im.uwrkaxlmjj.ui.hui.contacts;

import android.view.View;
import android.widget.FrameLayout;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.MryEmptyTextProgressView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhonebookUsersActivity_ViewBinding implements Unbinder {
    private PhonebookUsersActivity target;

    public PhonebookUsersActivity_ViewBinding(PhonebookUsersActivity target, View source) {
        this.target = target;
        target.listView = (RecyclerListView) Utils.findRequiredViewAsType(source, R.attr.listview, "field 'listView'", RecyclerListView.class);
        target.searchView = (MrySearchView) Utils.findRequiredViewAsType(source, R.attr.searchView, "field 'searchView'", MrySearchView.class);
        target.searchLayout = (FrameLayout) Utils.findRequiredViewAsType(source, R.attr.searchLayout, "field 'searchLayout'", FrameLayout.class);
        target.mEmptyView = (MryEmptyTextProgressView) Utils.findRequiredViewAsType(source, R.attr.emptyView, "field 'mEmptyView'", MryEmptyTextProgressView.class);
        target.mSideBar = (SideBar) Utils.findRequiredViewAsType(source, R.attr.sideBar, "field 'mSideBar'", SideBar.class);
        target.mTvChar = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tv_char, "field 'mTvChar'", MryTextView.class);
    }

    @Override // butterknife.Unbinder
    public void unbind() {
        PhonebookUsersActivity target = this.target;
        if (target == null) {
            throw new IllegalStateException("Bindings already cleared.");
        }
        this.target = null;
        target.listView = null;
        target.searchView = null;
        target.searchLayout = null;
        target.mEmptyView = null;
        target.mSideBar = null;
        target.mTvChar = null;
    }
}
