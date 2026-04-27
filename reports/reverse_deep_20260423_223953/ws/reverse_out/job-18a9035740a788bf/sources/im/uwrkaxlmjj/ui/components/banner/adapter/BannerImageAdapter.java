package im.uwrkaxlmjj.ui.components.banner.adapter;

import android.view.ViewGroup;
import android.widget.ImageView;
import im.uwrkaxlmjj.ui.components.banner.holder.BannerImageHolder;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public abstract class BannerImageAdapter<T> extends BannerAdapter<T, BannerImageHolder> {
    public BannerImageAdapter(List<T> mData) {
        super(mData);
    }

    @Override // im.uwrkaxlmjj.ui.components.banner.holder.IViewHolder
    public BannerImageHolder onCreateHolder(ViewGroup parent, int viewType) {
        ImageView imageView = new ImageView(parent.getContext());
        ViewGroup.LayoutParams params = new ViewGroup.LayoutParams(-1, -1);
        imageView.setLayoutParams(params);
        imageView.setScaleType(ImageView.ScaleType.CENTER_CROP);
        return new BannerImageHolder(imageView);
    }
}
