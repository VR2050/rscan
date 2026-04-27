package im.uwrkaxlmjj.ui.hui.friendscircle_v1.base;

import android.os.Bundle;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FragmentBackHandler;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.BackHandlerHelper;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public abstract class LazyLoadFragment extends Fragment implements FragmentBackHandler {
    private boolean isDataLoaded;
    private boolean isHidden = true;
    protected boolean isPaused = true;
    private boolean isViewCreated;
    private boolean isVisibleToUser;

    protected abstract void loadData();

    @Override // androidx.fragment.app.Fragment
    public void setUserVisibleHint(boolean isVisibleToUser) {
        super.setUserVisibleHint(isVisibleToUser);
        this.isVisibleToUser = isVisibleToUser;
        tryLoadData();
        checkIsVisible();
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        this.isViewCreated = true;
        tryLoadData();
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        if (this.isPaused) {
            this.isPaused = false;
            checkIsVisible();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        if (!this.isPaused) {
            this.isPaused = true;
            checkIsVisible();
        }
    }

    public void onResumeForBaseFragment() {
        if (this.isPaused) {
            this.isPaused = false;
            checkIsVisible();
        }
    }

    public void onPauseForBaseFragment() {
        if (!this.isPaused) {
            this.isPaused = true;
            checkIsVisible();
        }
    }

    public void checkLoadData() {
        if (!this.isDataLoaded) {
            tryLoadData();
        }
        checkIsVisible();
    }

    public void checkIsVisible() {
        if (this.isViewCreated && this.isDataLoaded) {
            if (isParentVisible() && this.isVisibleToUser && !this.isPaused) {
                onVisible();
            } else {
                onInvisible();
            }
        }
    }

    public void onVisible() {
    }

    public void onInvisible() {
    }

    public boolean isDataLoaded() {
        return this.isDataLoaded;
    }

    public boolean isVisibleToUser() {
        return this.isVisibleToUser;
    }

    @Override // androidx.fragment.app.Fragment
    public void onHiddenChanged(boolean hidden) {
        super.onHiddenChanged(hidden);
        this.isHidden = hidden;
        if (!hidden) {
            tryLoadData1();
        }
    }

    private boolean isParentVisible() {
        Fragment fragment = getParentFragment();
        return fragment == null || ((fragment instanceof LazyLoadFragment) && ((LazyLoadFragment) fragment).isVisibleToUser) || ((fragment instanceof BaseFmts) && ((BaseFmts) fragment).isFragmentVisible());
    }

    private void dispatchParentVisibleState() {
        FragmentManager fragmentManager = getChildFragmentManager();
        List<Fragment> fragments = fragmentManager.getFragments();
        if (fragments.isEmpty()) {
            return;
        }
        for (Fragment child : fragments) {
            if ((child instanceof LazyLoadFragment) && ((LazyLoadFragment) child).isVisibleToUser) {
                ((LazyLoadFragment) child).tryLoadData();
            }
        }
    }

    protected boolean isNeedReload() {
        return false;
    }

    public void tryLoadData() {
        if (this.isViewCreated && this.isVisibleToUser && isParentVisible()) {
            if (isNeedReload() || !this.isDataLoaded) {
                loadData();
                this.isDataLoaded = true;
                dispatchParentVisibleState();
            }
        }
    }

    private void dispatchParentHiddenState() {
        FragmentManager fragmentManager = getChildFragmentManager();
        List<Fragment> fragments = fragmentManager.getFragments();
        if (fragments.isEmpty()) {
            return;
        }
        for (Fragment child : fragments) {
            if ((child instanceof LazyLoadFragment) && !((LazyLoadFragment) child).isHidden) {
                ((LazyLoadFragment) child).tryLoadData1();
            }
        }
    }

    private boolean isParentHidden() {
        Fragment fragment = getParentFragment();
        if (fragment == null) {
            return false;
        }
        if ((fragment instanceof LazyLoadFragment) && !((LazyLoadFragment) fragment).isHidden) {
            return false;
        }
        return true;
    }

    public void tryLoadData1() {
        if (isParentHidden()) {
            return;
        }
        if (isNeedReload() || !this.isDataLoaded) {
            loadData();
            this.isDataLoaded = true;
            dispatchParentHiddenState();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        this.isViewCreated = false;
        this.isVisibleToUser = false;
        this.isDataLoaded = false;
        this.isHidden = true;
        this.isPaused = true;
        super.onDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FragmentBackHandler
    public boolean onBackPressed() {
        return BackHandlerHelper.handleBackPress(this);
    }
}
