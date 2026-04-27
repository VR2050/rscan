package im.uwrkaxlmjj.ui.actionbar;

import android.animation.ObjectAnimator;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.helper.MryDisplayHelper;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;

/* JADX INFO: loaded from: classes5.dex */
public abstract class BaseSearchViewFragment extends BaseFragment implements MrySearchView.ISearchViewDelegate {
    protected boolean mblnMove;
    protected MrySearchView searchView;

    protected abstract MrySearchView getSearchView();

    public BaseSearchViewFragment() {
        this.mblnMove = true;
    }

    public BaseSearchViewFragment(Bundle args) {
        super(args);
        this.mblnMove = true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onBeginSlide() {
        super.onBeginSlide();
        closeSearchView();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.searchView = getSearchView();
        initSearchView();
        return super.createView(context);
    }

    protected void initSearchView() {
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null) {
            mrySearchView.setiSearchViewDelegate(this);
        }
    }

    public void onStart(boolean focus) {
        if (this.mblnMove) {
            if (focus) {
                hideTitle(this.fragmentView);
            } else {
                showTitle(this.fragmentView);
            }
        }
    }

    public void onSearchExpand() {
    }

    @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public boolean canCollapseSearch() {
        return true;
    }

    public void onSearchCollapse() {
    }

    public void onTextChange(String value) {
    }

    public void onActionSearch(String trim) {
    }

    public void hideTitle(View rootView) {
        if (rootView == null) {
            return;
        }
        ObjectAnimator animator = ObjectAnimator.ofFloat(rootView, "translationY", 0.0f, -ActionBar.getCurrentActionBarHeight());
        animator.setDuration(300L);
        animator.start();
        if (this.actionBar != null) {
            this.actionBar.setVisibility(4);
        }
        RecyclerListView rv_list = (RecyclerListView) rootView.findViewWithTag("rv_list");
        if (rv_list != null) {
            rootView.getLayoutParams().height = MryDisplayHelper.getScreenHeight(getParentActivity()) + ActionBar.getCurrentActionBarHeight();
            rv_list.getLayoutParams().height = rv_list.getHeight() + ActionBar.getCurrentActionBarHeight();
        }
    }

    public void showTitle(View rootView) {
        if (rootView == null) {
            return;
        }
        ObjectAnimator animator = ObjectAnimator.ofFloat(rootView, "translationY", -ActionBar.getCurrentActionBarHeight(), 0.0f);
        animator.setDuration(300L);
        animator.start();
        if (this.actionBar != null) {
            this.actionBar.setVisibility(0);
        }
        RecyclerListView rv_list = (RecyclerListView) rootView.findViewWithTag("rv_list");
        if (rv_list != null) {
            rootView.getLayoutParams().height = MryDisplayHelper.getScreenHeight(getParentActivity());
            rv_list.getLayoutParams().height = rv_list.getHeight() - ActionBar.getCurrentActionBarHeight();
        }
    }

    public void closeSearchView() {
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
            return false;
        }
        return super.onBackPressed();
    }
}
