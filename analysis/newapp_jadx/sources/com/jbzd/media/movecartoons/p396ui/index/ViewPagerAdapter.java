package com.jbzd.media.movecartoons.p396ui.index;

import android.util.SparseArray;
import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentStatePagerAdapter;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B5\u0012\u0006\u0010\u001d\u001a\u00020\u001c\u0012\u001a\u0010\u001a\u001a\u0016\u0012\u0006\b\u0001\u0012\u00020\u00040\u0018j\n\u0012\u0006\b\u0001\u0012\u00020\u0004`\u0019\u0012\b\b\u0002\u0010\u001e\u001a\u00020\u0002¢\u0006\u0004\b\u001f\u0010 J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u001f\u0010\f\u001a\u00020\u000b2\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\f\u0010\rJ'\u0010\u0010\u001a\u00020\u000f2\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u000e\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u0017\u0010\u0012\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0012\u0010\u0006J\u0017\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u000e\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\u0013\u0010\u0014R\u001c\u0010\u0016\u001a\b\u0012\u0004\u0012\u00020\u00040\u00158\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0016\u0010\u0017R*\u0010\u001a\u001a\u0016\u0012\u0006\b\u0001\u0012\u00020\u00040\u0018j\n\u0012\u0006\b\u0001\u0012\u00020\u0004`\u00198\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001a\u0010\u001b¨\u0006!"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "Landroidx/fragment/app/FragmentStatePagerAdapter;", "", "position", "Landroidx/fragment/app/Fragment;", "getItem", "(I)Landroidx/fragment/app/Fragment;", "getCount", "()I", "Landroid/view/ViewGroup;", "container", "", "instantiateItem", "(Landroid/view/ViewGroup;I)Ljava/lang/Object;", "object", "", "destroyItem", "(Landroid/view/ViewGroup;ILjava/lang/Object;)V", "getFragment", "getItemPosition", "(Ljava/lang/Object;)I", "Landroid/util/SparseArray;", "frs", "Landroid/util/SparseArray;", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "fragments", "Ljava/util/ArrayList;", "Landroidx/fragment/app/FragmentManager;", "fm", "behavior", "<init>", "(Landroidx/fragment/app/FragmentManager;Ljava/util/ArrayList;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ViewPagerAdapter extends FragmentStatePagerAdapter {

    @NotNull
    private final ArrayList<? extends Fragment> fragments;

    @NotNull
    private final SparseArray<Fragment> frs;

    public /* synthetic */ ViewPagerAdapter(FragmentManager fragmentManager, ArrayList arrayList, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(fragmentManager, arrayList, (i3 & 4) != 0 ? 1 : i2);
    }

    @Override // androidx.fragment.app.FragmentStatePagerAdapter, androidx.viewpager.widget.PagerAdapter
    public void destroyItem(@NotNull ViewGroup container, int position, @NotNull Object object) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(object, "object");
        super.destroyItem(container, position, object);
        this.frs.removeAt(position);
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public int getCount() {
        return this.fragments.size();
    }

    @Nullable
    public final Fragment getFragment(int position) {
        return this.frs.get(position);
    }

    @Override // androidx.fragment.app.FragmentStatePagerAdapter
    @NotNull
    public Fragment getItem(int position) {
        return this.fragments.get(position);
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public int getItemPosition(@NotNull Object object) {
        Intrinsics.checkNotNullParameter(object, "object");
        return -2;
    }

    @Override // androidx.fragment.app.FragmentStatePagerAdapter, androidx.viewpager.widget.PagerAdapter
    @NotNull
    public Object instantiateItem(@NotNull ViewGroup container, int position) {
        Intrinsics.checkNotNullParameter(container, "container");
        Fragment fragment = (Fragment) super.instantiateItem(container, position);
        this.frs.put(position, fragment);
        return fragment;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ViewPagerAdapter(@NotNull FragmentManager fm, @NotNull ArrayList<? extends Fragment> fragments, int i2) {
        super(fm, i2);
        Intrinsics.checkNotNullParameter(fm, "fm");
        Intrinsics.checkNotNullParameter(fragments, "fragments");
        this.fragments = fragments;
        this.frs = new SparseArray<>(fragments.size());
    }
}
