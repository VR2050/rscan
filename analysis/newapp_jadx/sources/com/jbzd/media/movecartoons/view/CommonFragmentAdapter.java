package com.jbzd.media.movecartoons.view;

import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentStatePagerAdapter;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\r\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B+\u0012\u0006\u0010\u0015\u001a\u00020\u0014\u0012\f\u0010\r\u001a\b\u0012\u0004\u0012\u00020\u00060\f\u0012\f\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00110\f¢\u0006\u0004\b\u0016\u0010\u0017J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\n\u001a\u00020\t2\u0006\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u000bR\u001f\u0010\r\u001a\b\u0012\u0004\u0012\u00020\u00060\f8\u0006@\u0006¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010R\u001f\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00110\f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0012\u0010\u000e\u001a\u0004\b\u0013\u0010\u0010¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/CommonFragmentAdapter;", "Landroidx/fragment/app/FragmentStatePagerAdapter;", "", "getCount", "()I", "position", "Landroidx/fragment/app/Fragment;", "getItem", "(I)Landroidx/fragment/app/Fragment;", "", "getPageTitle", "(I)Ljava/lang/CharSequence;", "", "fragmentList", "Ljava/util/List;", "getFragmentList", "()Ljava/util/List;", "", "titles", "getTitles", "Landroidx/fragment/app/FragmentManager;", "fragmentManager", "<init>", "(Landroidx/fragment/app/FragmentManager;Ljava/util/List;Ljava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommonFragmentAdapter extends FragmentStatePagerAdapter {

    @NotNull
    private final List<Fragment> fragmentList;

    @NotNull
    private final List<String> titles;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public CommonFragmentAdapter(@NotNull FragmentManager fragmentManager, @NotNull List<? extends Fragment> fragmentList, @NotNull List<String> titles) {
        super(fragmentManager, 1);
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(fragmentList, "fragmentList");
        Intrinsics.checkNotNullParameter(titles, "titles");
        this.fragmentList = fragmentList;
        this.titles = titles;
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public int getCount() {
        return this.titles.size();
    }

    @NotNull
    public final List<Fragment> getFragmentList() {
        return this.fragmentList;
    }

    @Override // androidx.fragment.app.FragmentStatePagerAdapter
    @NotNull
    public Fragment getItem(int position) {
        return this.fragmentList.get(position);
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    @NotNull
    public CharSequence getPageTitle(int position) {
        return this.titles.get(position);
    }

    @NotNull
    public final List<String> getTitles() {
        return this.titles;
    }
}
