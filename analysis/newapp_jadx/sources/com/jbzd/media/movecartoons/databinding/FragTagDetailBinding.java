package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragTagDetailBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final ConstraintLayout llMineTop;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvPostdetailNickname;

    private FragTagDetailBinding(@NonNull ConstraintLayout constraintLayout, @NonNull CircleImageView circleImageView, @NonNull ConstraintLayout constraintLayout2, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = constraintLayout;
        this.civHead = circleImageView;
        this.llMineTop = constraintLayout2;
        this.tvDesc = textView;
        this.tvPostdetailNickname = textView2;
    }

    @NonNull
    public static FragTagDetailBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            ConstraintLayout constraintLayout = (ConstraintLayout) view;
            i2 = R.id.tv_desc;
            TextView textView = (TextView) view.findViewById(R.id.tv_desc);
            if (textView != null) {
                i2 = R.id.tv_postdetail_nickname;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                if (textView2 != null) {
                    return new FragTagDetailBinding(constraintLayout, circleImageView, constraintLayout, textView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragTagDetailBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragTagDetailBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_tag_detail, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
