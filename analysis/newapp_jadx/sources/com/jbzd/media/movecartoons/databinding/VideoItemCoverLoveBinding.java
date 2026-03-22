package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoItemCoverLoveBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvClicks;

    @NonNull
    public final ImageTextView itvLimitFree;

    @NonNull
    public final ImageTextView itvLove;

    @NonNull
    public final ImageTextView itvPrice;

    @NonNull
    public final ImageTextView itvType;

    @NonNull
    public final ImageTextView itvZhiding;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final TextView tvDuration;

    private VideoItemCoverLoveBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull ImageTextView imageTextView5, @NonNull ImageTextView imageTextView6, @NonNull TextView textView) {
        this.rootView = relativeLayout;
        this.itvClicks = imageTextView;
        this.itvLimitFree = imageTextView2;
        this.itvLove = imageTextView3;
        this.itvPrice = imageTextView4;
        this.itvType = imageTextView5;
        this.itvZhiding = imageTextView6;
        this.tvDuration = textView;
    }

    @NonNull
    public static VideoItemCoverLoveBinding bind(@NonNull View view) {
        int i2 = R.id.itv_clicks;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_clicks);
        if (imageTextView != null) {
            i2 = R.id.itv_limit_free;
            ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_limit_free);
            if (imageTextView2 != null) {
                i2 = R.id.itv_love;
                ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_love);
                if (imageTextView3 != null) {
                    i2 = R.id.itv_price;
                    ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_price);
                    if (imageTextView4 != null) {
                        i2 = R.id.itv_type;
                        ImageTextView imageTextView5 = (ImageTextView) view.findViewById(R.id.itv_type);
                        if (imageTextView5 != null) {
                            i2 = R.id.itv_zhiding;
                            ImageTextView imageTextView6 = (ImageTextView) view.findViewById(R.id.itv_zhiding);
                            if (imageTextView6 != null) {
                                i2 = R.id.tv_duration;
                                TextView textView = (TextView) view.findViewById(R.id.tv_duration);
                                if (textView != null) {
                                    return new VideoItemCoverLoveBinding((RelativeLayout) view, imageTextView, imageTextView2, imageTextView3, imageTextView4, imageTextView5, imageTextView6, textView);
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static VideoItemCoverLoveBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoItemCoverLoveBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_item_cover_love, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
