package com.gyf.barlibrary;

import androidx.fragment.app.Fragment;

/* JADX INFO: loaded from: classes.dex */
@Deprecated
public abstract class ImmersionFragment extends Fragment {
    @Deprecated
    protected abstract void immersionInit();

    @Override // androidx.fragment.app.Fragment
    public void setUserVisibleHint(boolean isVisibleToUser) {
        super.setUserVisibleHint(isVisibleToUser);
        if (isVisibleToUser && isResumed()) {
            onResume();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        if (getUserVisibleHint() && immersionEnabled()) {
            immersionInit();
        }
    }

    @Deprecated
    protected boolean immersionEnabled() {
        return true;
    }
}
