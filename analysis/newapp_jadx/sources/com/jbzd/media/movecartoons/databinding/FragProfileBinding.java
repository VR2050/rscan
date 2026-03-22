package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragProfileBinding implements ViewBinding {

    @NonNull
    public final ImageView ivUserUp;

    @NonNull
    public final ImageView ivUserVip;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvPostdetailNickname;

    private FragProfileBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.ivUserUp = imageView;
        this.ivUserVip = imageView2;
        this.tvPostdetailNickname = textView;
    }

    @NonNull
    public static FragProfileBinding bind(@NonNull View view) {
        int i2 = R.id.iv_user_up;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_user_up);
        if (imageView != null) {
            i2 = R.id.iv_user_vip;
            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_user_vip);
            if (imageView2 != null) {
                i2 = R.id.tv_postdetail_nickname;
                TextView textView = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                if (textView != null) {
                    return new FragProfileBinding((LinearLayout) view, imageView, imageView2, textView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragProfileBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragProfileBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_profile, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
