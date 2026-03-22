package com.jbzd.media.movecartoons.utils.banner;

import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.BannerMedia;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.adapter.BannerAdapter;
import com.youth.banner.util.BannerUtils;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0004\u0018\u00002\u0012\u0012\u0006\u0012\u0004\u0018\u00010\u0002\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u0001J\u0017\u0010\u0006\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0006\u0010\u0007¨\u0006\b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/banner/MultipleTypesAdapter;", "Lcom/youth/banner/adapter/BannerAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/BannerMedia;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "", "position", "getItemViewType", "(I)I", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MultipleTypesAdapter extends BannerAdapter<BannerMedia, RecyclerView.ViewHolder> {
    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        BannerMedia realData = getRealData(position);
        Intrinsics.checkNotNull(realData);
        return realData.getViewType();
    }

    @Override // com.youth.banner.holder.IViewHolder
    public void onBindView(Object obj, Object obj2, int i2, int i3) {
        RecyclerView.ViewHolder viewHolder = (RecyclerView.ViewHolder) obj;
        Integer valueOf = Integer.valueOf(viewHolder.getItemViewType());
        if (valueOf != null && valueOf.intValue() == 1) {
            throw null;
        }
        if (valueOf != null && valueOf.intValue() == 2) {
            throw null;
        }
    }

    @Override // com.youth.banner.holder.IViewHolder
    public Object onCreateHolder(ViewGroup parent, int i2) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        if (i2 == 1) {
            View view = BannerUtils.getView(parent, R.layout.banner_image);
            Intrinsics.checkNotNullExpressionValue(view, "getView(parent, R.layout.banner_image)");
            return new ImageHolder(view);
        }
        if (i2 != 2) {
            View view2 = BannerUtils.getView(parent, R.layout.banner_image);
            Intrinsics.checkNotNullExpressionValue(view2, "getView(parent, R.layout.banner_image)");
            return new ImageHolder(view2);
        }
        View view3 = BannerUtils.getView(parent, R.layout.banner_video);
        Intrinsics.checkNotNullExpressionValue(view3, "getView(parent, R.layout.banner_video)");
        return new VideoHolder(view3);
    }
}
