package im.uwrkaxlmjj.ui.adapters;

import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentStatePagerAdapter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class BaseVPAdapter<T> extends FragmentStatePagerAdapter {
    private List<T> mData;
    private List<Fragment> mFragments;

    public BaseVPAdapter(FragmentManager fm, T... mData) {
        this(fm, new ArrayList(Arrays.asList(mData)));
    }

    public BaseVPAdapter(FragmentManager fm, List<T> mData) {
        this(fm, mData, null);
    }

    public BaseVPAdapter(FragmentManager fm, List<T> mData, List<Fragment> mFragments) {
        super(fm);
        this.mData = mData;
        this.mFragments = mFragments;
    }

    public Fragment getIMItem(int position) {
        return null;
    }

    @Override // androidx.fragment.app.FragmentStatePagerAdapter
    public Fragment getItem(int position) {
        List<Fragment> list = this.mFragments;
        if (list != null && position >= 0 && position < list.size()) {
            return this.mFragments.get(position);
        }
        return getIMItem(position);
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public int getItemPosition(Object object) {
        return -2;
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public int getCount() {
        List<T> list = this.mData;
        if (list == null) {
            return 0;
        }
        return list.size();
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public CharSequence getPageTitle(int position) {
        List<T> list = this.mData;
        return list != null ? list.get(position).toString() : "";
    }

    public void setData(List<T> mData) {
        this.mData = mData;
    }

    public T getDataItem(int position) {
        List<T> list = this.mData;
        if (list == null || position < 0 || position > list.size()) {
            return null;
        }
        return this.mData.get(position);
    }

    public void setDataAndNotify(List<T> mData) {
        this.mData = mData;
        notifyDataSetChanged();
    }

    public void destroy() {
        if (this.mFragments != null) {
            this.mFragments = null;
        }
        if (this.mData != null) {
            this.mData = null;
        }
    }
}
