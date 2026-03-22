package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class LayoutCaverMsgAdBinding implements ViewBinding {

    @NonNull
    public final ImageView ivAdClose;

    @NonNull
    public final ImageView ivAdImg;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final TextView tvAdTime;

    private LayoutCaverMsgAdBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull TextView textView) {
        this.rootView = relativeLayout;
        this.ivAdClose = imageView;
        this.ivAdImg = imageView2;
        this.tvAdTime = textView;
    }

    @NonNull
    public static LayoutCaverMsgAdBinding bind(@NonNull View view) {
        int i2 = R.id.iv_adClose;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_adClose);
        if (imageView != null) {
            i2 = R.id.iv_adImg;
            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_adImg);
            if (imageView2 != null) {
                i2 = R.id.tv_adTime;
                TextView textView = (TextView) view.findViewById(R.id.tv_adTime);
                if (textView != null) {
                    return new LayoutCaverMsgAdBinding((RelativeLayout) view, imageView, imageView2, textView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutCaverMsgAdBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutCaverMsgAdBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.layout_caver_msg_ad, viewGroup, false);
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
