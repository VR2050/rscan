package com.preview;

import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import com.preview.PhotoPreviewFragment;

/* JADX INFO: loaded from: classes2.dex */
public class PhotoPreviewPagerAdapter extends BaseFragmentPagerAdapter {
    private PhotoPreviewFragment currentFragment;
    private PhotoPreviewFragment.OnExitListener mFragmentOnExitListener;
    private OnUpdateFragmentDataListener mOnUpdateFragmentDataListener;
    private int size;

    public interface OnUpdateFragmentDataListener {
        void onUpdate(PhotoPreviewFragment photoPreviewFragment, int i);
    }

    public PhotoPreviewPagerAdapter(FragmentManager fm, int size) {
        super(fm);
        this.size = size;
    }

    public PhotoPreviewFragment getCurrentFragment() {
        return this.currentFragment;
    }

    @Override // com.preview.BaseFragmentPagerAdapter, androidx.viewpager.widget.PagerAdapter
    public void setPrimaryItem(ViewGroup container, int position, Object object) {
        this.currentFragment = (PhotoPreviewFragment) object;
        super.setPrimaryItem(container, position, object);
    }

    @Override // com.preview.BaseFragmentPagerAdapter
    public Fragment getItem(int position) {
        PhotoPreviewFragment fragment = new PhotoPreviewFragment();
        fragment.setOnExitListener(this.mFragmentOnExitListener);
        return fragment;
    }

    @Override // com.preview.BaseFragmentPagerAdapter, androidx.viewpager.widget.PagerAdapter
    public Object instantiateItem(ViewGroup container, int position) {
        OnUpdateFragmentDataListener onUpdateFragmentDataListener;
        Object item = super.instantiateItem(container, position);
        if ((item instanceof PhotoPreviewFragment) && (onUpdateFragmentDataListener = this.mOnUpdateFragmentDataListener) != null) {
            onUpdateFragmentDataListener.onUpdate((PhotoPreviewFragment) item, position);
        }
        return item;
    }

    @Override // com.preview.BaseFragmentPagerAdapter
    public boolean dataIsChange(Object object) {
        return true;
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public int getCount() {
        return this.size;
    }

    public void setOnUpdateFragmentDataListener(OnUpdateFragmentDataListener onUpdateFragmentDataListener) {
        this.mOnUpdateFragmentDataListener = onUpdateFragmentDataListener;
    }

    public void setFragmentOnExitListener(PhotoPreviewFragment.OnExitListener fragmentOnExitListener) {
        this.mFragmentOnExitListener = fragmentOnExitListener;
    }

    public void setData(int size) {
        this.size = size;
        notifyDataSetChanged();
    }
}
